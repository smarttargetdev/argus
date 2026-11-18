import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import dotenv from 'dotenv';
import express from 'express';
import { createServer as createViteServer } from 'vite';
import {
  db,
  dbStats,
  type IdentityProviderRow,
  type SystemRow,
  type UserRow,
} from './server/db.ts';
import {
  decryptSecret,
  ensureRsaKeys,
  getJwtIssuer,
  hashPassword,
  issueSystemJwt,
  maskIp,
  sha256Hex,
  verifyIncomingJwt,
  verifyPassword,
  verifyTotpToken,
} from './server/cryptoAuth.ts';
import {
  buildEdgeCacheKey,
  computeEffectiveCacheTtl,
  getEdgeCached,
  getKvSystemPolicyVersion,
  getKvUserPermVersion,
  recordEdgeCacheOutcome,
  setEdgeCached,
} from './server/edgeCache.ts';
import { graphqlHandler } from './server/graphql.ts';
import { recordStructuredAudit, sseTelemetryHandler } from './server/telemetry.ts';
import { createCloudflareBundleZip, getCloudflareBundleFiles } from './server/cloudflareExport.ts';
import { getPlatformSettings, getPublicPlatformConfig } from './server/settings.ts';

dotenv.config();

const PORT = Number(process.env.PORT || 3000);
const failedLoginTracker = new Map<string, { count: number; resetAt: number }>();

function getAppUrl(req: express.Request): string {
  const configuredBase = getPlatformSettings().appBaseUrl;
  if (configuredBase) return configuredBase.replace(/\/$/, '');
  if (process.env.APP_URL) return process.env.APP_URL.replace(/\/$/, '');
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const host = req.headers['x-forwarded-host'] || req.get('host') || `localhost:${PORT}`;
  return `${proto}://${host}`;
}

function getSystemBySlugOrId(identifier?: string): SystemRow | undefined {
  dbStats.totalReads += 1;
  if (!identifier) {
    return db.prepare("SELECT * FROM systems WHERE slug = 'secure-gate' AND status = 'active'").get() as
      | SystemRow
      | undefined;
  }
  return db
    .prepare('SELECT * FROM systems WHERE (id = ? OR slug = ? OR client_id = ?) AND status = ?')
    .get(identifier, identifier, identifier, 'active') as SystemRow | undefined;
}

function createSessionAndAudit(params: {
  user: UserRow;
  system: SystemRow;
  jti: string;
  expiresAt: string;
  authMethod: string;
  req: express.Request;
}) {
  const { user, system, jti, expiresAt, authMethod, req } = params;
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO sessions (id, user_id, system_id, jti, auth_method, ip_masked, user_agent, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    `ses_${crypto.randomBytes(6).toString('hex')}`,
    user.id,
    system.id,
    jti,
    authMethod,
    maskIp(req.ip),
    String(req.headers['user-agent'] || 'VektorClient/1.0').slice(0, 120),
    expiresAt,
    now
  );
  db.prepare('UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?').run(now, now, user.id);
  dbStats.totalWrites += 2;
}

function resolveAvailableMfaMethods(user: UserRow, system: SystemRow): string[] {
  const sysAllowed = JSON.parse(system.allowed_mfa_methods || '["totp","sms"]') as string[];
  const available: string[] = [];
  if (user.totp_enabled && sysAllowed.includes('totp')) available.push('totp');
  if (user.phone_verified && sysAllowed.includes('sms')) available.push('sms');
  if (user.backup_codes_hash && user.totp_enabled) available.push('backup_code');
  return available;
}

async function startServer() {
  await ensureRsaKeys();

  const app = express();
  app.set('trust proxy', true);
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: true }));

  // Health Check
  app.get('/api/health', (_req, res) => {
    const settings = getPlatformSettings();
    res.json({
      status: 'ok',
      engine: 'sqlite-wal',
      d1Ready: true,
      environment: settings.executionEnvironment,
      platformName: settings.platformName,
      timestamp: new Date().toISOString(),
    });
  });

  // Public Runtime Config (Safe subset for Login UI & Session Hooks)
  app.get('/api/public/config', (_req, res) => {
    res.json(getPublicPlatformConfig());
  });

  // OIDC Discovery & JWKS
  app.get('/.well-known/openid-configuration', (req, res) => {
    const base = getAppUrl(req);
    res.json({
      issuer: getJwtIssuer(),
      authorization_endpoint: `${base}/api/oauth/authorize`,
      token_endpoint: `${base}/api/oauth/token`,
      userinfo_endpoint: `${base}/api/oauth/userinfo`,
      jwks_uri: `${base}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256', 'HS256'],
      code_challenge_methods_supported: ['S256', 'plain'],
      claims_supported: ['sub', 'email', 'name', 'sys', 'roles', 'permissions', 'claims', 'amr'],
    });
  });

  app.get('/.well-known/jwks.json', async (_req, res) => {
    const { publicJwk } = await ensureRsaKeys();
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.json({ keys: [publicJwk] });
  });

  // Public Systems & IdPs list for Login UI & Sandbox
  app.get('/api/public/systems', (_req, res) => {
    dbStats.totalReads += 2;
    const systems = db
      .prepare(
        `SELECT id, name, slug, description, client_id, redirect_uris, allowed_grants,
                allowed_idps, jwt_ttl_seconds, signing_alg, require_mfa, allowed_mfa_methods,
                edge_cache_ttl, privacy_policy_version
         FROM systems WHERE status = 'active' ORDER BY created_at ASC`
      )
      .all() as SystemRow[];

    const idps = db
      .prepare('SELECT id, name, provider_type, issuer_url, scopes, simulation_mode, enabled FROM identity_providers WHERE enabled = 1')
      .all();

    res.json({
      platformConfig: getPublicPlatformConfig(),
      systems: systems.map((s) => ({
        id: s.id,
        name: s.name,
        slug: s.slug,
        description: s.description,
        clientId: s.client_id,
        redirectUris: JSON.parse(s.redirect_uris || '[]'),
        allowedGrants: JSON.parse(s.allowed_grants || '[]'),
        allowedIdps: JSON.parse(s.allowed_idps || '[]'),
        jwtTtlSeconds: s.jwt_ttl_seconds,
        signingAlg: s.signing_alg,
        requireMfa: Boolean(s.require_mfa),
        allowedMfaMethods: JSON.parse(s.allowed_mfa_methods || '["totp","sms"]'),
        edgeCacheTtl: s.edge_cache_ttl,
        privacyPolicyVersion: s.privacy_policy_version,
      })),
      identityProviders: idps,
    });
  });

  // Primary Login Endpoint (Password -> Conditional 2FA Challenge -> Scoped System JWT)
  app.post('/api/auth/login', async (req, res) => {
    const started = performance.now();
    const settings = getPlatformSettings();
    const { email, password, systemSlug } = (req.body || {}) as {
      email?: string;
      password?: string;
      systemSlug?: string;
    };

    if (!email || !password) {
      res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const failureState = failedLoginTracker.get(normalizedEmail);
    if (failureState && failureState.resetAt > Date.now() && failureState.count >= settings.maxLoginAttempts) {
      recordStructuredAudit({
        actorId: 'anonymous',
        actorEmail: normalizedEmail,
        systemSlug: systemSlug || 'global',
        action: 'AUTH_RATE_LIMIT_EXCEEDED',
        resourceType: 'session',
        resourceId: normalizedEmail,
        status: 'denied',
        durationMs: performance.now() - started,
        ip: req.ip,
        details: { maxLoginAttempts: settings.maxLoginAttempts },
      });
      res.status(429).json({
        error: `Limite de ${settings.maxLoginAttempts} tentativas de login atingido. Aguarde alguns minutos antes de tentar novamente.`,
      });
      return;
    }

    const system = getSystemBySlugOrId(systemSlug);
    if (!system) {
      res.status(404).json({ error: 'Sistema alvo não encontrado ou desativado.' });
      return;
    }

    dbStats.totalReads += 1;
    const user = db
      .prepare('SELECT * FROM users WHERE email = ?')
      .get(normalizedEmail) as UserRow | undefined;

    if (!user || user.status !== 'active' || !verifyPassword(password, user.password_hash)) {
      const nextCount = failureState && failureState.resetAt > Date.now() ? failureState.count + 1 : 1;
      failedLoginTracker.set(normalizedEmail, {
        count: nextCount,
        resetAt: Date.now() + 5 * 60 * 1000,
      });

      recordStructuredAudit({
        actorId: user?.id || 'anonymous',
        actorEmail: email,
        systemId: system.id,
        systemSlug: system.slug,
        action: 'AUTH_LOGIN_FAILED',
        resourceType: 'session',
        resourceId: system.slug,
        status: 'denied',
        durationMs: performance.now() - started,
        ip: req.ip,
        details: { attempt: nextCount, maxAttempts: settings.maxLoginAttempts },
      });
      res.status(401).json({ error: 'Credenciais inválidas ou conta indisponível.' });
      return;
    }

    failedLoginTracker.delete(normalizedEmail);

    // Ensure user has a binding in target system
    const bindingCount = db
      .prepare('SELECT COUNT(*) as cnt FROM user_system_bindings WHERE user_id = ? AND system_id = ?')
      .get(user.id, system.id) as { cnt: number };
    if (bindingCount.cnt === 0) {
      res.status(403).json({
        error: `Usuário não possui vínculo de acesso ao sistema ${system.name}.`,
      });
      return;
    }

    // Check 2FA requirement (global policy OR system policy OR user has active 2FA configured)
    const availableMethods = resolveAvailableMfaMethods(user, system);
    const mustChallengeMfa =
      Boolean(settings.globalRequireMfa) ||
      Boolean(system.require_mfa) ||
      Boolean(user.totp_enabled) ||
      (Boolean(user.phone_verified) && user.mfa_preferred_method === 'sms');

    if (mustChallengeMfa) {
      if (availableMethods.length === 0) {
        res.status(403).json({
          error: `O sistema ${system.name} exige 2FA obrigatório. Ative TOTP ou SMS no seu perfil acessando pelo ${settings.platformName} Core primeiro.`,
          code: 'MFA_ENROLLMENT_REQUIRED',
        });
        return;
      }

      const mfaToken = `mfa_${crypto.randomBytes(24).toString('hex')}`;
      const expiresAt = new Date(Date.now() + settings.oauthCodeTtlSeconds * 1000).toISOString();
      db.prepare(
        'INSERT INTO mfa_challenges (token, user_id, system_id, auth_method, expires_at) VALUES (?, ?, ?, ?, ?)'
      ).run(mfaToken, user.id, system.id, 'pwd', expiresAt);
      dbStats.totalWrites += 1;

      recordStructuredAudit({
        actorId: user.id,
        actorEmail: user.email,
        systemId: system.id,
        systemSlug: system.slug,
        action: 'AUTH_MFA_CHALLENGE_ISSUED',
        resourceType: 'mfa_challenge',
        resourceId: mfaToken.slice(0, 12),
        status: 'success',
        durationMs: performance.now() - started,
        ip: req.ip,
        details: { availableMethods },
      });

      res.json({
        requiresMfa: true,
        mfaToken,
        availableMethods,
        preferredMethod: user.mfa_preferred_method !== 'none' ? user.mfa_preferred_method : availableMethods[0],
        phoneMasked: user.phone_number ? `${user.phone_number.slice(0, 4)}****${user.phone_number.slice(-3)}` : null,
        system: { id: system.id, name: system.name, slug: system.slug },
      });
      return;
    }

    const issued = await issueSystemJwt({ user, system, amr: ['pwd'] });
    createSessionAndAudit({
      user,
      system,
      jti: issued.jti,
      expiresAt: issued.expiresAt,
      authMethod: 'pwd',
      req,
    });

    recordStructuredAudit({
      actorId: user.id,
      actorEmail: user.email,
      systemId: system.id,
      systemSlug: system.slug,
      action: 'AUTH_JWT_ISSUED',
      resourceType: 'session',
      resourceId: issued.jti,
      status: 'success',
      durationMs: performance.now() - started,
      ip: req.ip,
      details: { ttlSeconds: system.jwt_ttl_seconds, alg: system.signing_alg, roles: issued.resolved.roles },
    });

    res.json({
      requiresMfa: false,
      accessToken: issued.token,
      tokenType: 'Bearer',
      expiresIn: system.jwt_ttl_seconds,
      expiresAt: issued.expiresAt,
      system: { id: system.id, name: system.name, slug: system.slug, signingAlg: system.signing_alg },
      user: {
        id: user.id,
        email: user.email,
        displayName: user.display_name,
        roles: issued.resolved.roles,
        permissions: issued.resolved.permissions,
        claims: issued.resolved.customClaims,
      },
    });
  });

  // Self-Service User Registration (Controlled by allowSelfRegistration parameter; disabled by default)
  app.post('/api/auth/register', (req, res) => {
    const started = performance.now();
    const settings = getPlatformSettings();
    const { email, displayName, password, systemSlug } = (req.body || {}) as {
      email?: string;
      displayName?: string;
      password?: string;
      systemSlug?: string;
    };

    if (!settings.allowSelfRegistration) {
      recordStructuredAudit({
        actorId: 'anonymous',
        actorEmail: email || 'unknown',
        systemSlug: systemSlug || 'global',
        action: 'AUTH_SELF_REGISTER_BLOCKED',
        resourceType: 'user',
        resourceId: 'self-register',
        status: 'denied',
        durationMs: performance.now() - started,
        ip: req.ip,
        details: { reason: 'Public user registration is disabled on login' },
      });

      res.status(403).json({
        error: 'O registro de novos usuários no login não é permitido. Solicite a criação da conta ao administrador.',
      });
      return;
    }

    if (!email || !password || !displayName) {
      res.status(400).json({ error: 'E-mail, nome e senha são obrigatórios.' });
      return;
    }

    if (password.length < settings.globalPasswordMinLength) {
      res.status(400).json({
        error: `A senha deve ter pelo menos ${settings.globalPasswordMinLength} caracteres.`,
      });
      return;
    }

    const cleanEmail = email.trim().toLowerCase();
    const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(cleanEmail);
    if (exists) {
      res.status(409).json({ error: 'E-mail já cadastrado.' });
      return;
    }

    const system = getSystemBySlugOrId(systemSlug);
    if (!system) {
      res.status(404).json({ error: 'Sistema alvo não encontrado.' });
      return;
    }

    const defaultRole = db
      .prepare('SELECT id FROM roles WHERE system_id = ? ORDER BY is_default DESC, created_at ASC LIMIT 1')
      .get(system.id) as { id: string } | undefined;

    const userId = `usr-${crypto.randomBytes(4).toString('hex')}`;
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO users (
        id, email, display_name, password_hash, phone_number, phone_verified,
        mfa_preferred_method, totp_secret_enc, totp_enabled, backup_codes_hash,
        status, perm_version, created_at, updated_at
      ) VALUES (?, ?, ?, ?, NULL, 0, 'none', NULL, 0, NULL, 'active', 1, ?, ?)
    `).run(userId, cleanEmail, displayName.trim(), hashPassword(password), now, now);

    if (defaultRole) {
      db.prepare('INSERT INTO user_system_bindings (id, user_id, system_id, role_id, created_at) VALUES (?, ?, ?, ?, ?)').run(
        `bnd-${crypto.randomBytes(4).toString('hex')}`,
        userId,
        system.id,
        defaultRole.id,
        now
      );
    }
    dbStats.totalWrites += defaultRole ? 2 : 1;

    recordStructuredAudit({
      actorId: userId,
      actorEmail: cleanEmail,
      systemId: system.id,
      systemSlug: system.slug,
      action: 'AUTH_SELF_REGISTERED',
      resourceType: 'user',
      resourceId: userId,
      status: 'success',
      durationMs: performance.now() - started,
      ip: req.ip,
    });

    res.status(201).json({ registered: true, userId, email: cleanEmail });
  });

  // Dispatch Login SMS OTP
  app.post('/api/auth/mfa/send-sms', (req, res) => {
    const settings = getPlatformSettings();
    const { mfaToken } = (req.body || {}) as { mfaToken?: string };
    if (!mfaToken) {
      res.status(400).json({ error: 'mfaToken obrigatório.' });
      return;
    }

    const challenge = db
      .prepare('SELECT * FROM mfa_challenges WHERE token = ? AND verified_at IS NULL')
      .get(mfaToken) as { user_id: string; system_id: string; expires_at: string } | undefined;

    if (!challenge || new Date(challenge.expires_at).getTime() < Date.now()) {
      res.status(401).json({ error: 'Desafio 2FA expirado ou inválido.' });
      return;
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(challenge.user_id) as UserRow | undefined;
    if (!user || !user.phone_number || !user.phone_verified) {
      res.status(400).json({ error: 'Telefone verificado não encontrado para envio de SMS.' });
      return;
    }

    const code = String(crypto.randomInt(100000, 999999));
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + settings.smsOtpTtlSeconds * 1000).toISOString();
    db.prepare(
      'INSERT INTO sms_otps (id, user_id, phone_number, code_hash, purpose, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(`sms-${crypto.randomBytes(4).toString('hex')}`, user.id, user.phone_number, sha256Hex(code), 'login', expiresAt, now);
    dbStats.totalWrites += 1;

    recordStructuredAudit({
      actorId: user.id,
      actorEmail: user.email,
      systemId: challenge.system_id,
      action: 'MFA_LOGIN_SMS_SENT',
      resourceType: 'mfa_challenge',
      resourceId: mfaToken.slice(0, 12),
      status: 'success',
      ip: req.ip,
    });

    res.json({
      sent: true,
      maskedPhone: `${user.phone_number.slice(0, 4)}****${user.phone_number.slice(-3)}`,
      expiresInSeconds: settings.smsOtpTtlSeconds,
      sandboxCodePreview: settings.smsSandboxPreview ? code : '',
    });
  });

  // Verify 2FA Challenge (TOTP, SMS OTP, or Backup Code) & Issue Final JWT (or unlock OAuth code)
  app.post('/api/auth/mfa/verify', async (req, res) => {
    const started = performance.now();
    const { mfaToken, method, code } = (req.body || {}) as {
      mfaToken?: string;
      method?: 'totp' | 'sms' | 'backup_code';
      code?: string;
    };

    if (!mfaToken || !method || !code) {
      res.status(400).json({ error: 'mfaToken, method e code sao obrigatorios.' });
      return;
    }

    const challenge = db
      .prepare('SELECT * FROM mfa_challenges WHERE token = ? AND verified_at IS NULL')
      .get(mfaToken) as
      | { token: string; user_id: string; system_id: string; auth_method: string; oauth_code: string | null; expires_at: string }
      | undefined;

    if (!challenge || new Date(challenge.expires_at).getTime() < Date.now()) {
      res.status(401).json({ error: 'Desafio 2FA expirado ou ja utilizado.' });
      return;
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(challenge.user_id) as UserRow | undefined;
    const system = db.prepare('SELECT * FROM systems WHERE id = ?').get(challenge.system_id) as SystemRow | undefined;
    if (!user || !system) {
      res.status(404).json({ error: 'Contexto de usuario/sistema nao encontrado.' });
      return;
    }

    let valid = false;
    if (method === 'totp') {
      if (!user.totp_enabled || !user.totp_secret_enc) {
        res.status(400).json({ error: 'TOTP nao habilitado para este usuario.' });
        return;
      }
      const secret = decryptSecret(user.totp_secret_enc);
      valid = verifyTotpToken(secret, code);
    } else if (method === 'sms') {
      const otpRow = db
        .prepare(
          `SELECT * FROM sms_otps
           WHERE user_id = ? AND purpose = 'login' AND consumed_at IS NULL
           ORDER BY created_at DESC LIMIT 1`
        )
        .get(user.id) as { id: string; code_hash: string; expires_at: string } | undefined;
      if (otpRow && new Date(otpRow.expires_at).getTime() >= Date.now() && otpRow.code_hash === sha256Hex(code.trim())) {
        valid = true;
        db.prepare('UPDATE sms_otps SET consumed_at = ? WHERE id = ?').run(new Date().toISOString(), otpRow.id);
      }
    } else if (method === 'backup_code') {
      const hashes = JSON.parse(user.backup_codes_hash || '[]') as string[];
      const targetHash = sha256Hex(code.trim().toUpperCase());
      const idx = hashes.indexOf(targetHash);
      if (idx !== -1) {
        valid = true;
        hashes.splice(idx, 1);
        db.prepare('UPDATE users SET backup_codes_hash = ? WHERE id = ?').run(JSON.stringify(hashes), user.id);
      }
    }

    if (!valid) {
      recordStructuredAudit({
        actorId: user.id,
        actorEmail: user.email,
        systemId: system.id,
        systemSlug: system.slug,
        action: 'AUTH_MFA_VERIFY_FAILED',
        resourceType: 'mfa_challenge',
        resourceId: mfaToken.slice(0, 12),
        status: 'denied',
        durationMs: performance.now() - started,
        ip: req.ip,
        details: { method },
      });
      res.status(401).json({ error: 'Codigo de verificacao 2FA invalido.' });
      return;
    }

    const now = new Date().toISOString();
    db.prepare('UPDATE mfa_challenges SET verified_at = ? WHERE token = ?').run(now, mfaToken);
    if (challenge.oauth_code) {
      db.prepare('UPDATE oauth_codes SET mfa_verified = 1 WHERE code = ?').run(challenge.oauth_code);
    }
    dbStats.totalWrites += 1;

    const amr = [challenge.auth_method, `mfa:${method}`];
    const issued = await issueSystemJwt({ user, system, amr });
    createSessionAndAudit({ user, system, jti: issued.jti, expiresAt: issued.expiresAt, authMethod: amr.join('+'), req });

    recordStructuredAudit({
      actorId: user.id,
      actorEmail: user.email,
      systemId: system.id,
      systemSlug: system.slug,
      action: 'AUTH_MFA_VERIFIED_JWT_ISSUED',
      resourceType: 'session',
      resourceId: issued.jti,
      status: 'success',
      durationMs: performance.now() - started,
      ip: req.ip,
      details: { method, amr, ttlSeconds: system.jwt_ttl_seconds },
    });

    res.json({
      verified: true,
      oauthCode: challenge.oauth_code,
      accessToken: issued.token,
      tokenType: 'Bearer',
      expiresIn: system.jwt_ttl_seconds,
      expiresAt: issued.expiresAt,
      system: { id: system.id, name: system.name, slug: system.slug, signingAlg: system.signing_alg },
      user: {
        id: user.id,
        email: user.email,
        displayName: user.display_name,
        roles: issued.resolved.roles,
        permissions: issued.resolved.permissions,
        claims: issued.resolved.customClaims,
      },
    });
  });

  // OAuth 2.0 Authorization Endpoint (PKCE + Conditional 2FA)
  app.post('/api/oauth/authorize', (req, res) => {
    const started = performance.now();
    const settings = getPlatformSettings();
    const {
      clientId,
      redirectUri,
      scope = 'openid profile email',
      codeChallenge,
      codeChallengeMethod = 'S256',
      email,
      password,
    } = (req.body || {}) as {
      clientId?: string;
      redirectUri?: string;
      scope?: string;
      codeChallenge?: string;
      codeChallengeMethod?: string;
      email?: string;
      password?: string;
    };

    if (!clientId || !email || !password) {
      res.status(400).json({ error: 'clientId, email e password são obrigatórios no fluxo OAuth.' });
      return;
    }

    if (settings.pkceRequired && !codeChallenge) {
      res.status(400).json({ error: 'Política global exige PKCE (codeChallenge) neste fluxo OAuth 2.0.' });
      return;
    }

    const system = getSystemBySlugOrId(clientId);
    if (!system) {
      res.status(404).json({ error: 'Sistema OAuth (client_id) não encontrado.' });
      return;
    }

    const allowedUris = JSON.parse(system.redirect_uris || '[]') as string[];
    const finalRedirect = redirectUri || allowedUris[0] || 'http://localhost:3000/oauth/sandbox';
    if (redirectUri && allowedUris.length > 0 && !allowedUris.includes(redirectUri)) {
      res.status(400).json({ error: 'redirect_uri não autorizada na política do sistema.' });
      return;
    }

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.trim().toLowerCase()) as UserRow | undefined;
    if (!user || user.status !== 'active' || !verifyPassword(password, user.password_hash)) {
      res.status(401).json({ error: 'Credenciais inválidas para autorização OAuth 2.0.' });
      return;
    }

    const bindingCount = db
      .prepare('SELECT COUNT(*) as cnt FROM user_system_bindings WHERE user_id = ? AND system_id = ?')
      .get(user.id, system.id) as { cnt: number };
    if (bindingCount.cnt === 0) {
      res.status(403).json({ error: `Usuário não autorizado no sistema ${system.name}.` });
      return;
    }

    const code = `ac_${crypto.randomBytes(20).toString('hex')}`;
    const expiresAt = new Date(Date.now() + settings.oauthCodeTtlSeconds * 1000).toISOString();
    const availableMethods = resolveAvailableMfaMethods(user, system);
    const mustChallengeMfa =
      Boolean(settings.globalRequireMfa) ||
      Boolean(system.require_mfa) ||
      Boolean(user.totp_enabled) ||
      (Boolean(user.phone_verified) && user.mfa_preferred_method === 'sms');

    db.prepare(`
      INSERT INTO oauth_codes (
        code, system_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method,
        auth_method, mfa_verified, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'oauth_code', ?, ?)
    `).run(
      code,
      system.id,
      user.id,
      finalRedirect,
      scope,
      codeChallenge || null,
      codeChallengeMethod,
      mustChallengeMfa ? 0 : 1,
      expiresAt
    );
    dbStats.totalWrites += 1;

    if (mustChallengeMfa && availableMethods.length > 0) {
      const mfaToken = `mfa_${crypto.randomBytes(24).toString('hex')}`;
      db.prepare(
        'INSERT INTO mfa_challenges (token, user_id, system_id, auth_method, oauth_code, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
      ).run(mfaToken, user.id, system.id, 'oauth_code', code, expiresAt);

      res.json({
        requiresMfa: true,
        mfaToken,
        availableMethods,
        preferredMethod: user.mfa_preferred_method !== 'none' ? user.mfa_preferred_method : availableMethods[0],
        code,
        redirectUri: finalRedirect,
      });
      return;
    }

    recordStructuredAudit({
      actorId: user.id,
      actorEmail: user.email,
      systemId: system.id,
      systemSlug: system.slug,
      action: 'OAUTH_AUTHORIZATION_CODE_ISSUED',
      resourceType: 'oauth_code',
      resourceId: code.slice(0, 12),
      status: 'success',
      durationMs: performance.now() - started,
      ip: req.ip,
      details: { pkce: Boolean(codeChallenge), scope },
    });

    res.json({
      requiresMfa: false,
      code,
      redirectUri: finalRedirect,
      expiresIn: settings.oauthCodeTtlSeconds,
    });
  });

  // OAuth 2.0 Token Exchange Endpoint
  app.post('/api/oauth/token', async (req, res) => {
    const started = performance.now();
    const {
      grant_type,
      code,
      client_id,
      code_verifier,
      username,
      password,
    } = (req.body || {}) as Record<string, string>;

    const system = getSystemBySlugOrId(client_id);
    if (!system) {
      res.status(400).json({ error: 'invalid_client', error_description: 'client_id invalido.' });
      return;
    }

    if (grant_type === 'authorization_code') {
      const codeRow = db
        .prepare('SELECT * FROM oauth_codes WHERE code = ? AND system_id = ? AND consumed_at IS NULL')
        .get(code, system.id) as
        | {
            code: string;
            user_id: string;
            code_challenge: string | null;
            code_challenge_method: string | null;
            mfa_verified: number;
            expires_at: string;
          }
        | undefined;

      if (!codeRow || new Date(codeRow.expires_at).getTime() < Date.now()) {
        res.status(400).json({ error: 'invalid_grant', error_description: 'Codigo de autorizacao invalido ou expirado.' });
        return;
      }

      if (!codeRow.mfa_verified) {
        res.status(403).json({ error: 'mfa_required', error_description: 'Desafio 2FA pendente para este codigo OAuth.' });
        return;
      }

      if (codeRow.code_challenge) {
        if (!code_verifier) {
          res.status(400).json({ error: 'invalid_grant', error_description: 'code_verifier PKCE ausente.' });
          return;
        }
        const computed =
          codeRow.code_challenge_method === 'S256'
            ? crypto.createHash('sha256').update(code_verifier).digest('base64url')
            : code_verifier;
        if (computed !== codeRow.code_challenge) {
          res.status(400).json({ error: 'invalid_grant', error_description: 'Falha na verificacao PKCE code_verifier.' });
          return;
        }
      }

      db.prepare('UPDATE oauth_codes SET consumed_at = ? WHERE code = ?').run(new Date().toISOString(), code);
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(codeRow.user_id) as UserRow;
      const issued = await issueSystemJwt({ user, system, amr: ['oauth_code', ...(user.totp_enabled || user.phone_verified ? ['mfa'] : [])] });
      createSessionAndAudit({ user, system, jti: issued.jti, expiresAt: issued.expiresAt, authMethod: 'oauth_code', req });

      recordStructuredAudit({
        actorId: user.id,
        actorEmail: user.email,
        systemId: system.id,
        systemSlug: system.slug,
        action: 'OAUTH_TOKEN_EXCHANGED',
        resourceType: 'token',
        resourceId: issued.jti,
        status: 'success',
        durationMs: performance.now() - started,
        ip: req.ip,
        details: { grantType: grant_type, alg: system.signing_alg, ttl: system.jwt_ttl_seconds },
      });

      res.json({
        access_token: issued.token,
        token_type: 'Bearer',
        expires_in: system.jwt_ttl_seconds,
        scope: 'openid profile email',
      });
      return;
    }

    if (grant_type === 'password') {
      const user = db.prepare('SELECT * FROM users WHERE email = ?').get((username || '').trim().toLowerCase()) as
        | UserRow
        | undefined;
      if (!user || !verifyPassword(password || '', user.password_hash)) {
        res.status(401).json({ error: 'invalid_grant', error_description: 'Credenciais invalidas.' });
        return;
      }
      if (system.require_mfa || user.totp_enabled) {
        res.status(403).json({
          error: 'mfa_required',
          error_description: 'Sistema ou usuario exige 2FA. Utilize fluxo authorization_code ou /api/auth/login.',
        });
        return;
      }
      const issued = await issueSystemJwt({ user, system, amr: ['pwd'] });
      createSessionAndAudit({ user, system, jti: issued.jti, expiresAt: issued.expiresAt, authMethod: 'oauth_password', req });
      res.json({
        access_token: issued.token,
        token_type: 'Bearer',
        expires_in: system.jwt_ttl_seconds,
      });
      return;
    }

    res.status(400).json({ error: 'unsupported_grant_type' });
  });

  // OIDC UserInfo Endpoint with Edge Cache respecting JWT Expiry
  app.get('/api/oauth/userinfo', async (req, res) => {
    const started = performance.now();
    const authHeader = req.headers.authorization || '';
    const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const jwt = bearer ? await verifyIncomingJwt(bearer) : null;
    if (!jwt) {
      res.status(401).json({ error: 'invalid_token' });
      return;
    }

    const settings = getPlatformSettings();
    const sysRow = db.prepare('SELECT edge_cache_ttl FROM systems WHERE id = ?').get(jwt.systemId) as
      | { edge_cache_ttl: number }
      | undefined;
    const effectiveTtl = settings.edgeCacheEnabled
      ? computeEffectiveCacheTtl(sysRow?.edge_cache_ttl ?? settings.defaultEdgeCacheTtl, jwt.exp)
      : 0;
    const cacheKey = buildEdgeCacheKey({
      operation: 'oidc:userinfo',
      variablesJson: '{}',
      systemId: jwt.systemId,
      subjectId: jwt.sub,
      roleScopeHash: jwt.jti,
      userPermVer: getKvUserPermVersion(jwt.sub),
      sysPolVer: getKvSystemPolicyVersion(jwt.systemId),
    });

    if (effectiveTtl > 0) {
      const hit = getEdgeCached(cacheKey);
      if (hit.hit) {
        const ms = performance.now() - started;
        recordEdgeCacheOutcome('HIT', ms);
        res.setHeader('CF-Cache-Status', 'HIT');
        res.setHeader('X-Cache-TTL-Remaining', String(hit.remainingTtlSeconds ?? effectiveTtl));
        res.setHeader('X-Query-Duration-Ms', ms.toFixed(2));
        res.json(hit.payload);
        return;
      }
    }

    dbStats.totalReads += 1;
    const user = db.prepare('SELECT id, email, display_name, totp_enabled, phone_verified FROM users WHERE id = ?').get(jwt.sub) as
      | { id: string; email: string; display_name: string; totp_enabled: number; phone_verified: number }
      | undefined;
    if (!user) {
      res.status(404).json({ error: 'user_not_found' });
      return;
    }

    const payload = {
      sub: user.id,
      email: user.email,
      name: user.display_name,
      system: jwt.sys,
      roles: jwt.roles,
      permissions: jwt.permissions,
      claims: jwt.claims,
      mfa_enabled: Boolean(user.totp_enabled || user.phone_verified),
    };

    const ms = performance.now() - started;
    if (effectiveTtl > 0) {
      setEdgeCached({ key: cacheKey, payload, systemId: jwt.systemId, subjectId: jwt.sub, ttlSeconds: effectiveTtl });
      recordEdgeCacheOutcome('MISS', ms);
      res.setHeader('CF-Cache-Status', 'MISS');
    } else {
      recordEdgeCacheOutcome('BYPASS', ms);
      res.setHeader('CF-Cache-Status', 'BYPASS');
    }
    res.setHeader('X-Cache-TTL-Remaining', String(effectiveTtl));
    res.setHeader('X-Query-Duration-Ms', ms.toFixed(2));
    res.json(payload);
  });

  // Decode & Verify JWT for OAuth Sandbox
  app.post('/api/auth/decode-jwt', async (req, res) => {
    const { token } = (req.body || {}) as { token?: string };
    if (!token) {
      res.status(400).json({ error: 'Token obrigatorio.' });
      return;
    }
    const parts = token.split('.');
    if (parts.length !== 3) {
      res.status(400).json({ error: 'Formato JWT invalido.' });
      return;
    }
    try {
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      const verified = await verifyIncomingJwt(token);
      res.json({
        validSignature: Boolean(verified),
        header,
        payload,
        secondsRemaining: Math.max(0, Number(payload.exp || 0) - Math.floor(Date.now() / 1000)),
      });
    } catch {
      res.status(400).json({ error: 'Falha ao decodificar JWT.' });
    }
  });

  // External IdP OAuth / Simulation Routes
  app.get('/api/auth/idp/:provider/url', (req, res) => {
    const { provider } = req.params;
    const idp = db.prepare('SELECT * FROM identity_providers WHERE provider_type = ? AND enabled = 1').get(provider) as
      | IdentityProviderRow
      | undefined;

    if (!idp) {
      res.status(404).json({ error: 'Provedor externo nao habilitado.' });
      return;
    }

    if (idp.simulation_mode) {
      res.json({ simulation: true, provider: idp.provider_type, name: idp.name });
      return;
    }

    const redirectUri = `${getAppUrl(req)}/api/auth/idp/${provider}/callback`;
    const params = new URLSearchParams({
      client_id: idp.client_id,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: idp.scopes,
      state: crypto.randomBytes(12).toString('hex'),
    });
    res.json({ simulation: false, url: `${idp.auth_url}?${params.toString()}`, redirectUri });
  });

  app.get(['/api/auth/idp/:provider/callback', '/api/auth/idp/:provider/callback/'], (req, res) => {
    const { provider } = req.params;
    const { code } = req.query;
    res.send(`
      <html>
        <body style="background:#090D16;color:#F1F5F9;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;">
          <script>
            if (window.opener) {
              window.opener.postMessage({ type: 'VEKTOR_IDP_CALLBACK', provider: ${JSON.stringify(provider)}, code: ${JSON.stringify(String(code || ''))} }, '*');
              window.close();
            } else {
              window.location.href = '/';
            }
          </script>
          <p>Autenticacao externa concluida. Esta janela fechara automaticamente.</p>
        </body>
      </html>
    `);
  });

  app.post('/api/auth/idp/simulate', async (req, res) => {
    const started = performance.now();
    const { providerType, externalEmail, externalName, systemSlug } = (req.body || {}) as {
      providerType?: string;
      externalEmail?: string;
      externalName?: string;
      systemSlug?: string;
    };

    if (!providerType || !externalEmail) {
      res.status(400).json({ error: 'Provedor e e-mail externo sao obrigatorios.' });
      return;
    }

    const system = getSystemBySlugOrId(systemSlug);
    if (!system) {
      res.status(404).json({ error: 'Sistema nao encontrado.' });
      return;
    }

    const allowedIdps = JSON.parse(system.allowed_idps || '[]') as string[];
    if (!allowedIdps.includes(providerType)) {
      res.status(403).json({ error: `Provedor ${providerType} nao esta habilitado na politica de ${system.name}.` });
      return;
    }

    const settings = getPlatformSettings();
    const cleanEmail = externalEmail.trim().toLowerCase();
    let user = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail) as UserRow | undefined;
    const now = new Date().toISOString();

    if (!user) {
      if (!settings.jitProvisioningEnabled) {
        res.status(403).json({
          error: 'Provisionamento automático (JIT) para provedores externos está desativado nas configurações globais.',
        });
        return;
      }
      const userId = `usr-${crypto.randomBytes(4).toString('hex')}`;
      const defaultRole = db
        .prepare('SELECT id FROM roles WHERE system_id = ? ORDER BY is_default DESC, created_at ASC LIMIT 1')
        .get(system.id) as { id: string } | undefined;
      if (!defaultRole) {
        res.status(400).json({ error: 'Sistema não possui role padrão para provisionamento JIT.' });
        return;
      }

      db.prepare(`
        INSERT INTO users (
          id, email, display_name, password_hash, phone_number, phone_verified,
          mfa_preferred_method, totp_secret_enc, totp_enabled, backup_codes_hash,
          status, perm_version, created_at, updated_at
        ) VALUES (?, ?, ?, ?, NULL, 0, 'none', NULL, 0, NULL, 'active', 1, ?, ?)
      `).run(userId, cleanEmail, externalName?.trim() || cleanEmail.split('@')[0], hashPassword(crypto.randomBytes(16).toString('hex')), now, now);

      db.prepare('INSERT INTO user_system_bindings (id, user_id, system_id, role_id, created_at) VALUES (?, ?, ?, ?, ?)').run(
        `bnd-${crypto.randomBytes(4).toString('hex')}`,
        userId,
        system.id,
        defaultRole.id,
        now
      );
      dbStats.totalWrites += 2;
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId) as UserRow;
    }

    // Link external identity idempotently
    db.prepare(`
      INSERT OR IGNORE INTO external_identities (id, user_id, provider_type, external_subject, external_email, linked_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      `ext-${crypto.randomBytes(4).toString('hex')}`,
      user.id,
      providerType,
      sha256Hex(`${providerType}:${cleanEmail}`).slice(0, 16),
      cleanEmail,
      now
    );

    const availableMethods = resolveAvailableMfaMethods(user, system);
    const mustChallengeMfa =
      Boolean(settings.globalRequireMfa) ||
      Boolean(system.require_mfa) ||
      Boolean(user.totp_enabled) ||
      (Boolean(user.phone_verified) && user.mfa_preferred_method === 'sms');

    if (mustChallengeMfa && availableMethods.length > 0) {
      const mfaToken = `mfa_${crypto.randomBytes(24).toString('hex')}`;
      const expiresAt = new Date(Date.now() + settings.oauthCodeTtlSeconds * 1000).toISOString();
      db.prepare(
        'INSERT INTO mfa_challenges (token, user_id, system_id, auth_method, expires_at) VALUES (?, ?, ?, ?, ?)'
      ).run(mfaToken, user.id, system.id, `idp:${providerType}`, expiresAt);

      res.json({
        requiresMfa: true,
        mfaToken,
        availableMethods,
        preferredMethod: user.mfa_preferred_method !== 'none' ? user.mfa_preferred_method : availableMethods[0],
        phoneMasked: user.phone_number ? `${user.phone_number.slice(0, 4)}****${user.phone_number.slice(-3)}` : null,
        system: { id: system.id, name: system.name, slug: system.slug },
      });
      return;
    }

    const issued = await issueSystemJwt({ user, system, amr: [`idp:${providerType}`] });
    createSessionAndAudit({ user, system, jti: issued.jti, expiresAt: issued.expiresAt, authMethod: `idp:${providerType}`, req });

    recordStructuredAudit({
      actorId: user.id,
      actorEmail: user.email,
      systemId: system.id,
      systemSlug: system.slug,
      action: 'IDP_FEDERATED_LOGIN',
      resourceType: 'idp',
      resourceId: providerType,
      status: 'success',
      durationMs: performance.now() - started,
      ip: req.ip,
      details: { providerType, jitProvisioned: true },
    });

    res.json({
      requiresMfa: false,
      accessToken: issued.token,
      tokenType: 'Bearer',
      expiresIn: system.jwt_ttl_seconds,
      expiresAt: issued.expiresAt,
      system: { id: system.id, name: system.name, slug: system.slug, signingAlg: system.signing_alg },
      user: {
        id: user.id,
        email: user.email,
        displayName: user.display_name,
        roles: issued.resolved.roles,
        permissions: issued.resolved.permissions,
        claims: issued.resolved.customClaims,
      },
    });
  });

  // GraphQL Endpoint (All Admin CRUD + User Self-Service + Edge Cache)
  app.post('/graphql', (req, res) => {
    void graphqlHandler(req, res);
  });

  // Real-Time Activity & Telemetry SSE Stream
  app.get('/api/telemetry/stream', sseTelemetryHandler);

  // Cloudflare Workers + D1 + KV Deployment Bundle
  app.get('/api/cloudflare/bundle', (_req, res) => {
    res.json({ files: getCloudflareBundleFiles() });
  });

  app.get('/api/cloudflare/download', async (_req, res) => {
    const zipBuffer = await createCloudflareBundleZip();
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="smarties-gate-cloudflare-d1-bundle.zip"');
    res.send(zipBuffer);
  });

  // Vite Dev Middleware or Production Static Serving
  const isProd = process.env.NODE_ENV === 'production' && fs.existsSync(path.resolve(process.cwd(), 'dist'));
  if (isProd) {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(
      JSON.stringify({
        level: 'info',
        event: 'server.listening',
        port: PORT,
        engine: 'sqlite-wal',
        edgeCache: 'active',
        timestamp: new Date().toISOString(),
      })
    );
  });
}

startServer().catch((err) => {
  console.error('Failed to start Smarties Secure Gate server:', err);
  process.exit(1);
});
