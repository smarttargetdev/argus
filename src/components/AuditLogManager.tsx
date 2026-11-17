import React, { useEffect, useMemo, useState } from 'react';
import { Search, RefreshCw, Eye, X, Radio, Filter } from 'lucide-react';
import { gqlRequest } from '../lib/graphqlClient';
import type { AuditLog, IamSystem } from '../types/iam';

interface AuditLogManagerProps {
  token: string;
  onNotify: (msg: string) => void;
  refreshSignal?: number;
  onLogsUpdated?: (logs: AuditLog[]) => void;
}

const AUDIT_LOGS_QUERY = `
  query AuditLogExplorer($systemId: ID, $action: String, $limit: Int) {
    systems {
      id
      name
      slug
    }
    auditLogs(systemId: $systemId, action: $action, limit: $limit) {
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

export const AuditLogManager: React.FC<AuditLogManagerProps> = ({
  token,
  onNotify,
  refreshSignal = 0,
  onLogsUpdated,
}) => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [systems, setSystems] = useState<IamSystem[]>([]);
  const [loading, setLoading] = useState(true);
  const [sseConnected, setSseConnected] = useState(false);

  // Filters & Search
  const [searchTerm, setSearchTerm] = useState('');
  const [systemFilter, setSystemFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'success' | 'denied' | 'error'>('all');
  const [actionFilter, setActionFilter] = useState('');

  // Popup Detail Modal (Master/Details)
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);

  const loadLogs = async () => {
    setLoading(true);
    try {
      const { data } = await gqlRequest<{ systems: IamSystem[]; auditLogs: AuditLog[] }>({
        token,
        query: AUDIT_LOGS_QUERY,
        operationName: 'AuditLogExplorer',
        variables: {
          systemId: systemFilter || undefined,
          action: actionFilter || undefined,
          limit: 100,
        },
      });
      setSystems(data.systems);
      setLogs(data.auditLogs);
      onLogsUpdated?.(data.auditLogs);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro ao consultar logs de auditoria.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadLogs();
  }, [token, systemFilter, actionFilter, refreshSignal]);

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
        setLogs((prev) => {
          if (prev.some((item) => item.id === mapped.id)) return prev;
          const next = [mapped, ...prev.slice(0, 99)];
          onLogsUpdated?.(next);
          return next;
        });
      } catch {
        // ignore malformed stream payload
      }
    });
    es.onerror = () => setSseConnected(false);
    return () => es.close();
  }, [onLogsUpdated]);

  const filteredLogs = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    return logs.filter((log) => {
      if (statusFilter !== 'all' && log.status !== statusFilter) return false;
      if (systemFilter && log.systemId !== systemFilter) return false;
      if (actionFilter && !log.action.toLowerCase().includes(actionFilter.toLowerCase())) return false;
      if (!q) return true;
      return (
        log.action.toLowerCase().includes(q) ||
        log.traceId.toLowerCase().includes(q) ||
        log.actorMasked.toLowerCase().includes(q) ||
        log.resourceType.toLowerCase().includes(q) ||
        log.resourceId.toLowerCase().includes(q) ||
        (log.systemSlug || '').toLowerCase().includes(q) ||
        log.ipMasked.toLowerCase().includes(q)
      );
    });
  }, [logs, searchTerm, statusFilter, systemFilter, actionFilter]);

  return (
    <div className="bg-[#111827] border border-slate-800/90 rounded-lg overflow-hidden">
      {/* Header & Controls */}
      <div className="px-5 py-4 border-b border-slate-800/80 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <h2 className="text-sm font-semibold text-white">Logs de Auditoria e Eventos de Acesso</h2>
            <span className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
              <Radio className={`w-3.5 h-3.5 ${sseConnected ? 'text-emerald-400' : 'text-slate-500'}`} />
              <span>{sseConnected ? 'SSE ao vivo' : 'SSE offline'}</span>
              <span aria-hidden="true">·</span>
              <span className="tabular-nums">{filteredLogs.length} exibidos</span>
            </span>
          </div>
          <button
            type="button"
            onClick={() => void loadLogs()}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-[#090D16] hover:bg-slate-800 border border-slate-700/80 text-slate-200 rounded-md transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Recarregar</span>
          </button>
        </div>

        {/* Search & Filter Strip */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-12 gap-2.5">
          <div className="lg:col-span-5 relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Buscar por ação, traceId, ator, recurso ou IP..."
              className="w-full bg-[#090D16] border border-slate-700/80 rounded-md pl-8 pr-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-[#F6821F]"
            />
          </div>

          <div className="lg:col-span-3 flex items-center gap-1.5">
            <Filter className="w-3.5 h-3.5 text-slate-500 shrink-0" />
            <select
              value={systemFilter}
              onChange={(e) => setSystemFilter(e.target.value)}
              className="w-full bg-[#090D16] border border-slate-700/80 rounded-md px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-[#F6821F]"
            >
              <option value="">Todos os sistemas</option>
              {systems.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({s.slug})
                </option>
              ))}
            </select>
          </div>

          <div className="lg:col-span-2">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as 'all' | 'success' | 'denied' | 'error')}
              className="w-full bg-[#090D16] border border-slate-700/80 rounded-md px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-[#F6821F]"
            >
              <option value="all">Todos os status</option>
              <option value="success">success</option>
              <option value="denied">denied</option>
              <option value="error">error</option>
            </select>
          </div>

          <div className="lg:col-span-2">
            <select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              className="w-full bg-[#090D16] border border-slate-700/80 rounded-md px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-[#F6821F]"
            >
              <option value="">Todas as ações</option>
              <option value="LOGIN">Autenticação / Login</option>
              <option value="MFA">2FA / MFA</option>
              <option value="OAUTH">OAuth 2.0 / Token</option>
              <option value="USER">Usuários</option>
              <option value="SYSTEM">Sistemas</option>
              <option value="ROLE">RBAC / Roles</option>
              <option value="LGPD">LGPD / Consent</option>
              <option value="CACHE">Cache Borda</option>
            </select>
          </div>
        </div>
      </div>

      {/* Logs Table */}
      <div className="overflow-x-auto max-h-[460px] overflow-y-auto">
        <table className="w-full text-left border-collapse">
          <thead className="sticky top-0 bg-[#111827] border-b border-slate-800 text-[11px] text-slate-400">
            <tr>
              <th className="py-2.5 px-4 font-medium">Horário</th>
              <th className="py-2.5 px-4 font-medium">Evento / Trace</th>
              <th className="py-2.5 px-4 font-medium">Recurso</th>
              <th className="py-2.5 px-4 font-medium">Ator (PII Mascarado)</th>
              <th className="py-2.5 px-4 font-medium">Sistema</th>
              <th className="py-2.5 px-4 font-medium">Status</th>
              <th className="py-2.5 px-4 font-medium text-right">Duração</th>
              <th className="py-2.5 px-4 font-medium text-right">Detalhes</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-xs">
            {loading && logs.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-slate-500">
                  Carregando logs estruturados via GraphQL...
                </td>
              </tr>
            ) : filteredLogs.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-slate-500">
                  Nenhum evento encontrado para os filtros selecionados.
                </td>
              </tr>
            ) : (
              filteredLogs.map((log) => (
                <tr
                  key={log.id}
                  onClick={() => setSelectedLog(log)}
                  className="hover:bg-slate-800/35 cursor-pointer transition-colors"
                >
                  <td className="py-2.5 px-4 font-mono tabular-nums text-slate-400 whitespace-nowrap">
                    {new Date(log.createdAt).toLocaleTimeString('pt-BR')}
                  </td>
                  <td className="py-2.5 px-4">
                    <div className="font-mono text-slate-100">{log.action}</div>
                    <div className="text-[11px] font-mono text-slate-500">{log.traceId}</div>
                  </td>
                  <td className="py-2.5 px-4 font-mono text-slate-300">
                    <div>{log.resourceType}</div>
                    <div className="text-[11px] text-slate-500 truncate max-w-[140px]">{log.resourceId}</div>
                  </td>
                  <td className="py-2.5 px-4 font-mono text-slate-300">
                    <div>{log.actorMasked}</div>
                    <div className="text-[11px] text-slate-500">{log.ipMasked}</div>
                  </td>
                  <td className="py-2.5 px-4 font-mono text-slate-300 whitespace-nowrap">
                    {log.systemSlug || 'global'}
                  </td>
                  <td className="py-2.5 px-4 whitespace-nowrap font-mono">
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
                    <span className="text-slate-500"> · {log.cacheStatus}</span>
                  </td>
                  <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-300 whitespace-nowrap">
                    {log.durationMs.toFixed(2)} ms
                  </td>
                  <td className="py-2.5 px-4 text-right">
                    <button
                      type="button"
                      onClick={(ev) => {
                        ev.stopPropagation();
                        setSelectedLog(log);
                      }}
                      title="Inspecionar Log Estruturado"
                      className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
                    >
                      <Eye className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Master/Details Popup Modal for Audit Event Inspection */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="max-w-2xl w-full bg-[#111827] border border-slate-700 rounded-lg p-6 max-h-[90vh] overflow-y-auto space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="font-display text-base font-semibold text-white">
                  Detalhes do Evento · <span className="font-mono">{selectedLog.action}</span>
                </h3>
                <p className="text-xs font-mono text-slate-400 mt-0.5">
                  Trace {selectedLog.traceId} · LGPD PII-Safe · {new Date(selectedLog.createdAt).toLocaleString('pt-BR')}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setSelectedLog(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="bg-[#090D16] border border-slate-800 rounded p-2.5">
                <div className="text-slate-400 text-[11px]">Ator Mascarado</div>
                <div className="font-mono text-white mt-0.5 truncate">{selectedLog.actorMasked}</div>
              </div>
              <div className="bg-[#090D16] border border-slate-800 rounded p-2.5">
                <div className="text-slate-400 text-[11px]">IP Mascarado</div>
                <div className="font-mono text-white mt-0.5">{selectedLog.ipMasked}</div>
              </div>
              <div className="bg-[#090D16] border border-slate-800 rounded p-2.5">
                <div className="text-slate-400 text-[11px]">Status / Cache</div>
                <div className="font-mono text-white mt-0.5">
                  {selectedLog.status} · {selectedLog.cacheStatus}
                </div>
              </div>
              <div className="bg-[#090D16] border border-slate-800 rounded p-2.5">
                <div className="text-slate-400 text-[11px]">Duração</div>
                <div className="font-mono tabular-nums text-white mt-0.5">
                  {selectedLog.durationMs.toFixed(2)} ms
                </div>
              </div>
            </div>

            <pre className="bg-[#090D16] border border-slate-800 rounded-md p-3.5 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-80 leading-relaxed">
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

            <div className="flex justify-end pt-1">
              <button
                type="button"
                onClick={() => setSelectedLog(null)}
                className="px-4 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-white rounded-md"
              >
                Fechar
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
