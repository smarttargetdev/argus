import { useCallback, useEffect, useMemo, useState } from 'react';
import { gqlRequest } from '../lib/graphqlClient';

export type SystemHealthLevel = 'healthy' | 'degraded' | 'critical' | 'loading';

export interface SystemHealthState {
  level: SystemHealthLevel;
  label: string;
  avgLatencyMs: number | null;
  maxLatencyMs: number | null;
  sampleCount: number;
  errorCount: number;
}

interface RecentAuditSample {
  id: string;
  durationMs: number;
  status: string;
}

const AUDIT_HEALTH_QUERY = `
  query TopBarAuditHealth($limit: Int) {
    auditLogs(limit: $limit) {
      id
      durationMs
      status
    }
  }
`;

const SYSTEM_HEALTH_QUERY = `
  query TopBarSystemHealth($limit: Int) {
    systemHealth(limit: $limit) {
      status
      avgLatencyMs
      maxLatencyMs
      sampleCount
      errorCount
    }
  }
`;

const SAMPLE_WINDOW = 50;

export function classifyLatency(avgLatencyMs: number): {
  level: Exclude<SystemHealthLevel, 'loading'>;
  label: string;
} {
  if (avgLatencyMs >= 300) {
    return { level: 'critical', label: 'Latência Crítica' };
  }
  if (avgLatencyMs >= 100) {
    return { level: 'degraded', label: 'Atenção' };
  }
  return { level: 'healthy', label: 'Saudável' };
}

export function useSystemHealth(params: {
  token: string | null;
  canReadAuditLogs: boolean;
  telemetryStreamEnabled?: boolean;
  refreshSignal?: number;
}): SystemHealthState {
  const { token, canReadAuditLogs, telemetryStreamEnabled = true, refreshSignal = 0 } = params;

  const [samples, setSamples] = useState<RecentAuditSample[] | null>(null);
  const [fallbackHealth, setFallbackHealth] = useState<{
    avgLatencyMs: number;
    maxLatencyMs: number;
    sampleCount: number;
    errorCount: number;
  } | null>(null);

  const fetchHealth = useCallback(async () => {
    if (!token) return;
    try {
      if (canReadAuditLogs) {
        const { data } = await gqlRequest<{
          auditLogs: Array<{ id: string; durationMs: number; status: string }>;
        }>({
          token,
          query: AUDIT_HEALTH_QUERY,
          operationName: 'TopBarAuditHealth',
          variables: { limit: SAMPLE_WINDOW },
          bypassCache: true,
          silentDiagnostics: true,
        });
        setSamples(
          (data.auditLogs || []).map((row) => ({
            id: row.id,
            durationMs: Number(row.durationMs || 0),
            status: row.status,
          }))
        );
      } else {
        const { data } = await gqlRequest<{
          systemHealth: {
            avgLatencyMs: number;
            maxLatencyMs: number;
            sampleCount: number;
            errorCount: number;
          };
        }>({
          token,
          query: SYSTEM_HEALTH_QUERY,
          operationName: 'TopBarSystemHealth',
          variables: { limit: SAMPLE_WINDOW },
          bypassCache: true,
          silentDiagnostics: true,
        });
        setFallbackHealth(data.systemHealth);
      }
    } catch {
      // Non-fatal background health check; retains last known measurement
    }
  }, [token, canReadAuditLogs]);

  useEffect(() => {
    if (!token) {
      setSamples(null);
      setFallbackHealth(null);
      return;
    }

    fetchHealth();
    const interval = window.setInterval(fetchHealth, 20000);
    return () => window.clearInterval(interval);
  }, [token, refreshSignal, fetchHealth]);

  useEffect(() => {
    if (!token || !telemetryStreamEnabled) return;

    const es = new EventSource('/api/telemetry/stream');
    es.addEventListener('audit', (ev) => {
      try {
        const raw = JSON.parse((ev as MessageEvent).data) as {
          id?: string;
          duration_ms?: number;
          status?: string;
        };
        const nextSample: RecentAuditSample = {
          id: raw.id || `sse_${Date.now()}`,
          durationMs: Number(raw.duration_ms ?? 0),
          status: raw.status || 'success',
        };
        setSamples((prev) => {
          if (!prev) return [nextSample];
          if (prev.some((item) => item.id === nextSample.id)) return prev;
          return [nextSample, ...prev].slice(0, SAMPLE_WINDOW);
        });
      } catch {
        // Ignore malformed SSE payload
      }
    });

    return () => {
      es.close();
    };
  }, [token, telemetryStreamEnabled]);

  return useMemo(() => {
    if (samples !== null) {
      const sampleCount = samples.length;
      if (sampleCount === 0) {
        return {
          level: 'healthy',
          label: 'Saudável',
          avgLatencyMs: 0,
          maxLatencyMs: 0,
          sampleCount: 0,
          errorCount: 0,
        };
      }
      let sum = 0;
      let maxLatencyMs = 0;
      let errorCount = 0;
      for (const s of samples) {
        sum += s.durationMs;
        if (s.durationMs > maxLatencyMs) maxLatencyMs = s.durationMs;
        if (s.status === 'error') errorCount += 1;
      }
      const avgLatencyMs = Number((sum / sampleCount).toFixed(1));
      const classification = classifyLatency(avgLatencyMs);
      return {
        level: classification.level,
        label: classification.label,
        avgLatencyMs,
        maxLatencyMs: Number(maxLatencyMs.toFixed(1)),
        sampleCount,
        errorCount,
      };
    }

    if (fallbackHealth !== null) {
      const avgLatencyMs = Number(fallbackHealth.avgLatencyMs.toFixed(1));
      const classification = classifyLatency(avgLatencyMs);
      return {
        level: classification.level,
        label: classification.label,
        avgLatencyMs,
        maxLatencyMs: Number(fallbackHealth.maxLatencyMs.toFixed(1)),
        sampleCount: fallbackHealth.sampleCount,
        errorCount: fallbackHealth.errorCount,
      };
    }

    return {
      level: 'loading',
      label: 'Verificando',
      avgLatencyMs: null,
      maxLatencyMs: null,
      sampleCount: 0,
      errorCount: 0,
    };
  }, [samples, fallbackHealth]);
}
