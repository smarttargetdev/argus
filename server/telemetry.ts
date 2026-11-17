import type { Request, Response } from 'express';
import crypto from 'node:crypto';
import { dbStats, queueAuditLog, type AuditLogRow } from './db.ts';
import { hashSubjectForAudit, maskEmail, maskIp } from './cryptoAuth.ts';

const sseClients = new Set<Response>();

export function recordStructuredAudit(params: {
  actorId: string;
  actorEmail: string;
  systemId?: string | null;
  systemSlug?: string | null;
  action: string;
  resourceType: string;
  resourceId: string;
  status: 'success' | 'denied' | 'error';
  cacheStatus?: string;
  durationMs?: number;
  ip?: string;
  details?: Record<string, unknown>;
}): AuditLogRow {
  const entry: AuditLogRow = {
    id: `aud_${crypto.randomUUID()}`,
    trace_id: `tr_${crypto.randomBytes(6).toString('hex')}`,
    actor_hash: hashSubjectForAudit(params.actorId),
    actor_masked: maskEmail(params.actorEmail),
    system_id: params.systemId ?? null,
    system_slug: params.systemSlug ?? null,
    action: params.action,
    resource_type: params.resourceType,
    resource_id: params.resourceId,
    status: params.status,
    cache_status: params.cacheStatus ?? 'BYPASS',
    duration_ms: Number((params.durationMs ?? 0).toFixed(2)),
    ip_masked: maskIp(params.ip),
    details_json: JSON.stringify(params.details ?? {}),
    created_at: new Date().toISOString(),
  };

  queueAuditLog(entry);

  // Structured JSON log to stdout for edge log aggregation
  console.log(
    JSON.stringify({
      level: params.status === 'error' ? 'error' : params.status === 'denied' ? 'warn' : 'info',
      event: 'iam.audit',
      trace_id: entry.trace_id,
      action: entry.action,
      resource: `${entry.resource_type}:${entry.resource_id}`,
      system: entry.system_slug,
      actor_hash: entry.actor_hash,
      status: entry.status,
      cache_status: entry.cache_status,
      duration_ms: entry.duration_ms,
      timestamp: entry.created_at,
    })
  );

  // Real-time SSE push to connected admin monitors
  const sseData = `event: audit\ndata: ${JSON.stringify(entry)}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(sseData);
    } catch {
      sseClients.delete(client);
    }
  }

  return entry;
}

export function broadcastMetricsSnapshot(snapshot: Record<string, unknown>): void {
  const sseData = `event: metrics\ndata: ${JSON.stringify(snapshot)}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(sseData);
    } catch {
      sseClients.delete(client);
    }
  }
}

export function sseTelemetryHandler(req: Request, res: Response): void {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();

  sseClients.add(res);
  res.write(
    `event: connected\ndata: ${JSON.stringify({
      connectedAt: new Date().toISOString(),
      activeStreams: sseClients.size,
      queuedLogs: dbStats.queuedAuditLogs,
    })}\n\n`
  );

  const heartbeat = setInterval(() => {
    try {
      res.write(`event: heartbeat\ndata: ${JSON.stringify({ ts: Date.now() })}\n\n`);
    } catch {
      clearInterval(heartbeat);
      sseClients.delete(res);
    }
  }, 15000);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(res);
  });
}

export function getActiveSseCount(): number {
  return sseClients.size;
}
