import React, { useEffect, useState } from 'react';
import { RefreshCw, Trash2, Activity, Database, Zap, Radio } from 'lucide-react';
import { gqlRequest } from '../lib/graphqlClient';
import type { AuditLog, EdgeMetrics } from '../types/iam';

interface OverviewTelemetryProps {
  token: string;
  onNotify: (msg: string) => void;
}

const OVERVIEW_QUERY = `
  query OverviewTelemetry($limit: Int, $action: String) {
    edgeMetrics {
      cacheHits
      cacheMisses
      cacheBypasses
      cachePurges
      cachedEntriesCount
      cacheHitRatioPct
      kvVersionReads
      p50LatencyMs
      p95LatencyMs
      avgHitLatencyMs
      avgMissLatencyMs
      sqliteTotalReads
      sqliteTotalWrites
      sqliteReadRatioPct
      batchedAuditFlushes
      queuedAuditLogs
      activeSseStreams
    }
    auditLogs(limit: $limit, action: $action) {
      id
      traceId
      actorHash
      actorMasked
      systemId
      systemSlug
      action
      resourceType
      resourceId
      status
      cacheStatus
      durationMs
      ipMasked
      detailsJson
      createdAt
    }
  }
`;

export const OverviewTelemetry: React.FC<OverviewTelemetryProps> = ({ token, onNotify }) => {
  const [metrics, setMetrics] = useState<EdgeMetrics | null>(null);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [actionFilter, setActionFilter] = useState('');
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);
  const [sseConnected, setSseConnected] = useState(false);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    setLoading(true);
    try {
      const { data } = await gqlRequest<{ edgeMetrics: EdgeMetrics; auditLogs: AuditLog[] }>({
        token,
        query: OVERVIEW_QUERY,
        operationName: 'OverviewTelemetry',
        variables: { limit: 40, action: actionFilter || undefined },
      });
      setMetrics(data.edgeMetrics);
      setLogs(data.auditLogs);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro ao carregar telemetria GraphQL.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, [token, actionFilter]);

  useEffect(() => {
    const es = new EventSource('/api/telemetry/stream');
    es.addEventListener('connected', () => setSseConnected(true));
    es.addEventListener('audit', (ev) => {
      try {
        const raw = JSON.parse((ev as MessageEvent).data) as {
          id: string;
          trace_id: string;
          actor_hash: string;
          actor_masked: string;
          system_id: string | null;
          system_slug: string | null;
          action: string;
          resource_type: string;
          resource_id: string;
          status: 'success' | 'denied' | 'error';
          cache_status: string;
          duration_ms: number;
          ip_masked: string;
          details_json: string;
          created_at: string;
        };
        const mapped: AuditLog = {
          id: raw.id,
          traceId: raw.trace_id,
          actorHash: raw.actor_hash,
          actorMasked: raw.actor_masked,
          systemId: raw.system_id,
          systemSlug: raw.system_slug,
          action: raw.action,
          resourceType: raw.resource_type,
          resourceId: raw.resource_id,
          status: raw.status,
          cacheStatus: raw.cache_status,
          durationMs: raw.duration_ms,
          ipMasked: raw.ip_masked,
          detailsJson: raw.details_json,
          createdAt: raw.created_at,
        };
        setLogs((prev) => [mapped, ...prev.slice(0, 49)]);
      } catch {
        // ignore malformed stream payload
      }
    });
    es.onerror = () => setSseConnected(false);
    return () => es.close();
  }, []);

  const handlePurgeCache = async () => {
    try {
      const { data } = await gqlRequest<{ purgeEdgeCache: number }>({
        token,
        query: `mutation PurgeAll { purgeEdgeCache }`,
        operationName: 'PurgeAll',
      });
      onNotify(`Cache de borda invalidado (${data.purgeEdgeCache} entradas removidas).`);
      void loadData();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Sem permissao para purgar cache.');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-xl font-semibold text-white">Visão Geral e Telemetria na Borda</h1>
          <p className="text-xs text-slate-400 mt-1">
            Métricas reais de latência GraphQL, cache distribuído sensível a JWT e stream estruturado de auditoria.
          </p>
        </div>
        <div className="flex items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={() => void loadData()}
            className="flex items-center gap-2 px-3 py-2 text-xs font-medium bg-[#111827] hover:bg-slate-800 border border-slate-700/80 text-slate-200 rounded-md transition-colors whitespace-nowrap"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Atualizar</span>
          </button>
          <button
            type="button"
            onClick={handlePurgeCache}
            className="flex items-center gap-2 px-3 py-2 text-xs font-medium bg-[#F6821F] hover:bg-[#e27316] text-slate-950 rounded-md transition-colors whitespace-nowrap"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Purgar Cache de Borda</span>
          </button>
        </div>
      </div>

      {/* KPI Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#111827] border border-slate-800/90 rounded-lg p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Taxa de Acerto no Cache</span>
            <Zap className="w-3.5 h-3.5 text-[#F6821F]" />
          </div>
          <div className="font-mono tabular-nums text-2xl font-semibold text-white">
            {metrics ? `${metrics.cacheHitRatioPct}%` : '—'}
          </div>
          <div className="text-[11px] font-mono tabular-nums text-slate-400">
            {metrics ? `${metrics.cacheHits} HIT · ${metrics.cacheMisses} MISS · ${metrics.cachedEntriesCount} em RAM` : 'Carregando...'}
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800/90 rounded-lg p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Latência GraphQL (p50 / p95)</span>
            <Activity className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="font-mono tabular-nums text-2xl font-semibold text-white">
            {metrics ? `${metrics.p50LatencyMs} / ${metrics.p95LatencyMs} ms` : '—'}
          </div>
          <div className="text-[11px] font-mono tabular-nums text-slate-400">
            {metrics ? `Média HIT ${metrics.avgHitLatencyMs}ms · MISS ${metrics.avgMissLatencyMs}ms` : 'Carregando...'}
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800/90 rounded-lg p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Perfil SQLite WAL (Leitura)</span>
            <Database className="w-3.5 h-3.5 text-sky-400" />
          </div>
          <div className="font-mono tabular-nums text-2xl font-semibold text-white">
            {metrics ? `${metrics.sqliteReadRatioPct}%` : '—'}
          </div>
          <div className="text-[11px] font-mono tabular-nums text-slate-400">
            {metrics ? `${metrics.sqliteTotalReads} leituras · ${metrics.sqliteTotalWrites} gravações` : 'Carregando...'}
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800/90 rounded-lg p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>KV Versions & Audit Batch</span>
            <Radio className="w-3.5 h-3.5 text-slate-400" />
          </div>
          <div className="font-mono tabular-nums text-2xl font-semibold text-white">
            {metrics ? `${metrics.kvVersionReads}` : '—'}
          </div>
          <div className="text-[11px] font-mono tabular-nums text-slate-400">
            {metrics
              ? `${metrics.batchedAuditFlushes} lotes gravados · SSE ${sseConnected ? 'conectado' : 'reconectando'}`
              : 'Carregando...'}
          </div>
        </div>
      </div>

      {/* Live Audit Table + JSON Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className="lg:col-span-8 bg-[#111827] border border-slate-800/90 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <h2 className="text-sm font-semibold text-white">Relatório de Atividades em Tempo Real</h2>
              <span className="text-xs text-slate-400 font-mono">
                {sseConnected ? 'SSE ao vivo' : 'SSE offline'} · {logs.length} eventos
              </span>
            </div>
            <input
              type="text"
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              placeholder="Filtrar ação (ex: USER, AUTH, MFA)..."
              className="bg-[#090D16] border border-slate-700/80 rounded-md px-3 py-1.5 text-xs text-slate-200 w-56 focus:outline-none focus:border-[#F6821F]"
            />
          </div>

          <div className="overflow-x-auto max-h-[460px] overflow-y-auto">
            <table className="w-full text-left border-collapse">
              <thead className="sticky top-0 bg-[#111827] border-b border-slate-800 text-[11px] text-slate-400">
                <tr>
                  <th className="py-2.5 px-3 font-medium">Horário</th>
                  <th className="py-2.5 px-3 font-medium">Ação / Trace</th>
                  <th className="py-2.5 px-3 font-medium">Ator (PII Mascarado)</th>
                  <th className="py-2.5 px-3 font-medium">Sistema</th>
                  <th className="py-2.5 px-3 font-medium">Status</th>
                  <th className="py-2.5 px-3 font-medium text-right">Duração</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-xs">
                {loading && logs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500">
                      Carregando logs estruturados...
                    </td>
                  </tr>
                ) : logs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500">
                      Nenhum evento encontrado para o filtro atual.
                    </td>
                  </tr>
                ) : (
                  logs.map((log) => (
                    <tr
                      key={log.id}
                      onClick={() => setSelectedLog(log)}
                      className={`cursor-pointer transition-colors ${
                        selectedLog?.id === log.id ? 'bg-slate-800/70' : 'hover:bg-slate-800/35'
                      }`}
                    >
                      <td className="py-2.5 px-3 font-mono tabular-nums text-slate-400 whitespace-nowrap">
                        {new Date(log.createdAt).toLocaleTimeString('pt-BR')}
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="font-mono text-slate-100">{log.action}</div>
                        <div className="text-[11px] font-mono text-slate-500">{log.traceId}</div>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-slate-300">
                        <div>{log.actorMasked}</div>
                        <div className="text-[11px] text-slate-500">{log.ipMasked}</div>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300 font-mono">
                        {log.systemSlug || 'global'}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span
                          className={
                            log.status === 'success'
                              ? 'text-emerald-400'
                              : log.status === 'denied'
                                ? 'text-amber-400'
                                : 'text-red-400'
                          }
                        >
                          {log.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono tabular-nums text-slate-300 whitespace-nowrap">
                        {log.durationMs.toFixed(2)} ms
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Structured Log JSON Inspector */}
        <div className="lg:col-span-4 bg-[#111827] border border-slate-800/90 rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
            <h3 className="text-sm font-semibold text-white">Log Estruturado (JSON)</h3>
            <span className="text-[11px] font-mono text-slate-400">LGPD PII-Safe</span>
          </div>
          {selectedLog ? (
            <pre className="bg-[#090D16] border border-slate-800 rounded-md p-3 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-[390px] leading-relaxed">
              {JSON.stringify(
                {
                  ...selectedLog,
                  details: (() => {
                    try {
                      return JSON.parse(selectedLog.detailsJson);
                    } catch {
                      return selectedLog.detailsJson;
                    }
                  })(),
                },
                null,
                2
              )}
            </pre>
          ) : (
            <div className="py-12 text-center text-xs text-slate-500">
              Selecione qualquer linha na tabela ao lado para inspecionar o registro estruturado com mascaramento de dados pessoais.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
