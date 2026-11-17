import JSZip from 'jszip';
import { D1_SCHEMA_SQL } from './db.ts';

export interface CloudflareArtifactFile {
  path: string;
  language: string;
  description: string;
  content: string;
}

const WRANGLER_TOML = `name = "smarties-gate-edge-worker"
main = "src/worker.ts"
compatibility_date = "2026-03-01"
compatibility_flags = ["nodejs_compat"]

# Cloudflare D1 (SQLite na Borda)
[[d1_databases]]
binding = "DB"
database_name = "smarties-gate-d1"
database_id = "00000000-0000-0000-0000-000000000000"

# Cloudflare Workers KV (Versionamento de permissoes, revogacao JTI e rate limit)
[[kv_namespaces]]
binding = "IAM_KV"
id = "00000000000000000000000000000000"

[vars]
IAM_JWT_ISSUER = "https://iam.sua-empresa.workers.dev"
DEFAULT_EDGE_CACHE_TTL = "120"
`;

const WORKER_TS = `import { jwtVerify, SignJWT } from 'jose';
import { buildSchema, graphql } from 'graphql';

export interface Env {
  DB: D1Database;
  IAM_KV: KVNamespace;
  IAM_JWT_ISSUER: string;
  JWT_HMAC_FALLBACK: string;
}

const schema = buildSchema(\`
  type Query {
    systems: [System!]!
    users(systemId: ID): [User!]!
    me: User
  }
  type System {
    id: ID!
    name: String!
    slug: String!
    clientId: String!
    jwtTtlSeconds: Int!
    edgeCacheTtl: Int!
    requireMfa: Boolean!
    policyVersion: Int!
  }
  type User {
    id: ID!
    email: String!
    displayName: String!
    status: String!
    permVersion: Int!
  }
\`);

async function computeEdgeKey(parts: string[]): Promise<string> {
  const bytes = new TextEncoder().encode(parts.join('|'));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 32);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const started = performance.now();

    // 1. OAuth 2.0 / UserInfo & Edge GraphQL via JWT + Cache API + KV Versioning
    if (url.pathname === '/graphql' && request.method === 'POST') {
      const auth = request.headers.get('Authorization') || '';
      const token = auth.replace(/^Bearer\\s+/i, '');
      if (!token) {
        return Response.json({ errors: [{ message: 'Missing Bearer JWT' }] }, { status: 401 });
      }

      const secret = new TextEncoder().encode(env.JWT_HMAC_FALLBACK);
      const { payload } = await jwtVerify(token, secret, { issuer: env.IAM_JWT_ISSUER });
      const sub = String(payload.sub || '');
      const sysId = String(payload.system_id || '');
      const jwtExp = Number(payload.exp || 0);
      const nowSec = Math.floor(Date.now() / 1000);

      // Check KV revocation & permission version
      const [revoked, kvPermVer, kvPolVer] = await Promise.all([
        env.IAM_KV.get(\`revoked:\${payload.jti}\`),
        env.IAM_KV.get(\`u_ver:\${sub}\`),
        env.IAM_KV.get(\`s_ver:\${sysId}\`),
      ]);
      if (revoked) {
        return Response.json({ errors: [{ message: 'JWT revoked at edge' }] }, { status: 401 });
      }

      const body = (await request.json()) as { query: string; variables?: Record<string, unknown> };
      const isMutation = body.query.trim().startsWith('mutation');
      const cache = caches.default;

      if (!isMutation) {
        const edgeHash = await computeEdgeKey([
          body.query,
          JSON.stringify(body.variables || {}),
          sysId,
          sub,
          String(kvPermVer || payload.perm_ver || 1),
          String(kvPolVer || payload.pol_ver || 1),
        ]);
        const cacheReq = new Request(\`https://edge-cache.internal/gql/\${edgeHash}\`);
        const cached = await cache.match(cacheReq);
        if (cached) {
          const hitRes = new Response(cached.body, cached);
          hitRes.headers.set('CF-Cache-Status', 'HIT');
          hitRes.headers.set('X-Query-Duration-Ms', (performance.now() - started).toFixed(2));
          return hitRes;
        }

        // Execute batched D1 queries on Cache MISS
        const result = await graphql({
          schema,
          source: body.query,
          variableValues: body.variables,
          rootValue: {
            systems: async () => {
              const { results } = await env.DB.prepare(
                'SELECT id, name, slug, client_id as clientId, jwt_ttl_seconds as jwtTtlSeconds, edge_cache_ttl as edgeCacheTtl, require_mfa as requireMfa, policy_version as policyVersion FROM systems WHERE status = ?'
              ).bind('active').all();
              return results;
            },
            users: async ({ systemId }: { systemId?: string }) => {
              if (systemId) {
                const { results } = await env.DB.prepare(
                  'SELECT u.id, u.email, u.display_name as displayName, u.status, u.perm_version as permVersion FROM users u JOIN user_system_bindings b ON b.user_id = u.id WHERE b.system_id = ?'
                ).bind(systemId).all();
                return results;
              }
              const { results } = await env.DB.prepare(
                'SELECT id, email, display_name as displayName, status, perm_version as permVersion FROM users'
              ).all();
              return results;
            },
            me: async () => {
              return env.DB.prepare(
                'SELECT id, email, display_name as displayName, status, perm_version as permVersion FROM users WHERE id = ?'
              ).bind(sub).first();
            },
          },
        });

        const policyTtl = 120;
        const effectiveTtl = Math.max(0, Math.min(policyTtl, jwtExp - nowSec));
        const res = Response.json(result, {
          headers: {
            'Cache-Control': \`public, max-age=\${effectiveTtl}\`,
            'CF-Cache-Status': 'MISS',
            'X-Cache-TTL-Remaining': String(effectiveTtl),
            'X-Query-Duration-Ms': (performance.now() - started).toFixed(2),
          },
        });

        if (effectiveTtl > 0) {
          ctx.waitUntil(cache.put(cacheReq, res.clone()));
        }
        return res;
      }
    }

    // 2. OAuth Token Endpoint on Edge Worker
    if (url.pathname === '/api/oauth/token' && request.method === 'POST') {
      const secret = new TextEncoder().encode(env.JWT_HMAC_FALLBACK);
      const jwt = await new SignJWT({ sys: 'vektor-core', roles: ['member'] })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuer(env.IAM_JWT_ISSUER)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(secret);
      return Response.json({ access_token: jwt, token_type: 'Bearer', expires_in: 3600 });
    }

    return Response.json({ service: 'smarties-gate-edge-worker', status: 'ok' });
  },
};
`;

const DEPLOY_README = `# Smarties Gate — Pacote Cloudflare Workers + D1 + KV

1. Crie o banco D1 na Cloudflare:
   npx wrangler d1 create smarties-gate-d1

2. Aplique o schema SQL otimizado para leitura e indices de cobertura:
   npx wrangler d1 execute smarties-gate-d1 --file=./schema.d1.sql

3. Crie o namespace KV para versoes de permissoes e revogacao instantanea de JWT:
   npx wrangler kv namespace create IAM_KV

4. Atualize os IDs em wrangler.toml e publique na borda:
   npx wrangler deploy
`;

export function getCloudflareBundleFiles(): CloudflareArtifactFile[] {
  return [
    {
      path: 'wrangler.toml',
      language: 'toml',
      description: 'Manifesto Cloudflare Workers com bindings D1 (SQLite na borda) e Workers KV.',
      content: WRANGLER_TOML,
    },
    {
      path: 'schema.d1.sql',
      language: 'sql',
      description: 'Schema D1 completo com indices compostos de cobertura e tabelas LGPD/RBAC.',
      content: D1_SCHEMA_SQL.trim(),
    },
    {
      path: 'src/worker.ts',
      language: 'typescript',
      description: 'Edge Worker com verificacao JWT, Cache API limitada ao exp do token, KV versioning e GraphQL sobre D1.',
      content: WORKER_TS,
    },
    {
      path: 'README.md',
      language: 'markdown',
      description: 'Instrucoes de provisionamento D1, KV e deploy via Wrangler.',
      content: DEPLOY_README,
    },
  ];
}

export async function createCloudflareBundleZip(): Promise<Buffer> {
  const zip = new JSZip();
  for (const file of getCloudflareBundleFiles()) {
    zip.file(file.path, file.content);
  }
  return zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
}
