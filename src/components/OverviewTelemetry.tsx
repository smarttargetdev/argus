import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import * as d3 from 'd3';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from 'recharts';
import {
  RefreshCw,
  Trash2,
  Activity,
  Database,
  Zap,
  Radio,
  Users,
  KeyRound,
  ShieldAlert,
  TrendingUp,
  ServerCrash,
  AlertOctagon,
  Eye,
  X,
  CheckCheck,
  Timer,
} from 'lucide-react';
import { gqlRequest } from '../lib/graphqlClient';
import { AuditLogs } from './AuditLogs';
import { HealthHistoryPanel } from './HealthHistoryPanel';
import type {
  AuditLog,
  ComplianceSummary,
  DiagnosticHeaders,
  EdgeMetrics,
  IamSystem,
  IamUser,
  SystemHealthEvent,
} from '../types/iam';

interface OverviewTelemetryProps {
  token: string;
  onNotify: (msg: string, variant?: 'success' | 'error' | 'warning') => void;
}

type RefreshIntervalOption = 10000 | 30000 | 60000 | 0;

const OVERVIEW_BASE_QUERY = `
  query OverviewBaseTelemetry {
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
    complianceSummary {
      totalUsers
      anonymizedUsers
      activeConsents
      revokedConsents
      mfaAdoptedUsers
      totpUsers
      smsUsers
      piiMaskedLogsCount
    }
    systems {
      id
      name
      slug
    }
    me {
      id
      lastLoginAt
      sessions {
        id
        createdAt
        expiresAt
        revokedAt
      }
    }
    systemHealthHistory(limit: 50) {
      id
      previousStatus
      newStatus
      avgLatencyMs
      maxLatencyMs
      sampleCount
      errorCount
      reason
      createdAt
    }
  }
`;

const OVERVIEW_ADMIN_STATS_QUERY = `
  query OverviewAdminKeyStats {
    users(limit: 200) {
      id
      status
      lastLoginAt
      createdAt
      sessions {
        id
        createdAt
        expiresAt
        revokedAt
      }
    }
    auditLogs(limit: 200) {
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

interface KeyStatsState {
  activeUsers: number;
  totalUsers: number;
  mfaAdoptedUsers: number;
  validTokens: number;
  revokedOrExpiredTokens: number;
  recentWarnings: number;
  deniedCount: number;
  errorCount: number;
}

interface HourlyTrendPoint {
  hourDate: Date;
  label: string;
  activeUsers: number;
  activeSessions: number;
  eventsCount: number;
}

interface HttpStatusSystemRow {
  systemName: string;
  systemSlug: string;
  s2xx: number;
  s4xx: number;
  s5xx: number;
  total: number;
}

interface ActiveUsersTrendChartProps {
  data: HourlyTrendPoint[];
  diagnostics: DiagnosticHeaders | null;
}

const ActiveUsersTrendChart: React.FC<ActiveUsersTrendChartProps> = ({ data, diagnostics }) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [width, setWidth] = useState(760);
  const [hovered, setHovered] = useState<{ point: HourlyTrendPoint; x: number; y: number } | null>(null);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const observer = new ResizeObserver((entries) => {
      const nextWidth = entries[0]?.contentRect.width;
      if (nextWidth && nextWidth > 200) {
        setWidth(Math.floor(nextWidth));
      }
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const svgEl = svgRef.current;
    if (!svgEl || data.length === 0) return;

    const height = 220;
    const margin = { top: 16, right: 20, bottom: 28, left: 38 };
    const innerWidth = Math.max(120, width - margin.left - margin.right);
    const innerHeight = height - margin.top - margin.bottom;

    const svg = d3.select(svgEl);
    svg.selectAll('*').remove();

    const defs = svg.append('defs');
    const grad = defs
      .append('linearGradient')
      .attr('id', 'activeUsersAreaGrad')
      .attr('x1', '0%')
      .attr('y1', '0%')
      .attr('x2', '0%')
      .attr('y2', '100%');
    grad.append('stop').attr('offset', '0%').attr('stop-color', '#F6821F').attr('stop-opacity', 0.28);
    grad.append('stop').attr('offset', '100%').attr('stop-color', '#F6821F').attr('stop-opacity', 0.01);

    const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

    const xExtent = d3.extent(data, (d) => d.hourDate) as [Date, Date];
    const xScale = d3.scaleTime().domain(xExtent).range([0, innerWidth]);

    const maxUsers = d3.max(data, (d) => d.activeUsers) ?? 0;
    const yMax = Math.max(4, Math.ceil(maxUsers * 1.25));
    const yScale = d3.scaleLinear().domain([0, yMax]).nice().range([innerHeight, 0]);

    // Horizontal Gridlines
    const yTicks = yScale.ticks(4);
    g.append('g')
      .selectAll('line')
      .data(yTicks)
      .enter()
      .append('line')
      .attr('x1', 0)
      .attr('x2', innerWidth)
      .attr('y1', (d) => yScale(d))
      .attr('y2', (d) => yScale(d))
      .attr('stroke', 'rgba(148, 163, 184, 0.1)')
      .attr('stroke-dasharray', '3,3');

    // Axes
    const xAxis = d3
      .axisBottom<Date>(xScale)
      .ticks(6)
      .tickFormat((d) => d3.timeFormat('%H:%M')(d));
    const yAxis = d3.axisLeft<number>(yScale).ticks(4).tickFormat((d) => `${Math.round(d)}`);

    const xAxisG = g
      .append('g')
      .attr('transform', `translate(0,${innerHeight})`)
      .call(xAxis);
    xAxisG.selectAll('path, line').attr('stroke', 'rgba(148, 163, 184, 0.2)');
    xAxisG
      .selectAll('text')
      .attr('fill', '#94a3b8')
      .style('font-family', '"JetBrains Mono", monospace')
      .style('font-size', '10px');

    const yAxisG = g.append('g').call(yAxis);
    yAxisG.selectAll('path, line').attr('stroke', 'rgba(148, 163, 184, 0.2)');
    yAxisG
      .selectAll('text')
      .attr('fill', '#94a3b8')
      .style('font-family', '"JetBrains Mono", monospace')
      .style('font-size', '10px');

    // Area + Line
    const areaGen = d3
      .area<HourlyTrendPoint>()
      .x((d) => xScale(d.hourDate))
      .y0(innerHeight)
      .y1((d) => yScale(d.activeUsers))
      .curve(d3.curveMonotoneX);

    const lineGen = d3
      .line<HourlyTrendPoint>()
      .x((d) => xScale(d.hourDate))
      .y((d) => yScale(d.activeUsers))
      .curve(d3.curveMonotoneX);

    g.append('path').datum(data).attr('fill', 'url(#activeUsersAreaGrad)').attr('d', areaGen);

    g.append('path')
      .datum(data)
      .attr('fill', 'none')
      .attr('stroke', '#F6821F')
      .attr('stroke-width', 2)
      .attr('d', lineGen);

    // Data point dots
    g.selectAll('circle.trend-dot')
      .data(data)
      .enter()
      .append('circle')
      .attr('class', 'trend-dot')
      .attr('cx', (d) => xScale(d.hourDate))
      .attr('cy', (d) => yScale(d.activeUsers))
      .attr('r', 2.8)
      .attr('fill', '#090D16')
      .attr('stroke', '#F6821F')
      .attr('stroke-width', 1.5);

    // Interactive hover overlay
    const focusLine = g
      .append('line')
      .attr('y1', 0)
      .attr('y2', innerHeight)
      .attr('stroke', 'rgba(246, 130, 31, 0.45)')
      .attr('stroke-dasharray', '2,2')
      .style('opacity', 0);

    const bisectDate = d3.bisector<HourlyTrendPoint, Date>((d) => d.hourDate).left;

    g.append('rect')
      .attr('width', innerWidth)
      .attr('height', innerHeight)
      .attr('fill', 'transparent')
      .style('cursor', 'crosshair')
      .on('mousemove', (event: MouseEvent) => {
        const [mx] = d3.pointer(event);
        const hoveredDate = xScale.invert(mx);
        const idx = bisectDate(data, hoveredDate, 1);
        const d0 = data[idx - 1];
        const d1 = data[idx];
        const closest =
          !d1 || !d0
            ? d0 || d1
            : hoveredDate.getTime() - d0.hourDate.getTime() > d1.hourDate.getTime() - hoveredDate.getTime()
              ? d1
              : d0;

        if (!closest) return;
        const cx = xScale(closest.hourDate);
        const cy = yScale(closest.activeUsers);
        focusLine.attr('x1', cx).attr('x2', cx).style('opacity', 1);
        setHovered({ point: closest, x: margin.left + cx, y: margin.top + cy });
      })
      .on('mouseleave', () => {
        focusLine.style('opacity', 0);
        setHovered(null);
      });
  }, [data, width]);

  const peakUsers = useMemo(() => Math.max(0, ...data.map((d) => d.activeUsers)), [data]);
  const currentUsers = data.length > 0 ? data[data.length - 1].activeUsers : 0;

  return (
    <section
      aria-label="Tendência de Usuários Ativos nas Últimas 24 Horas"
      className="bg-[#111827] border border-slate-800/90 rounded-lg p-5 space-y-4"
    >
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2.5">
          <TrendingUp className="w-4 h-4 text-[#F6821F]" />
          <div>
            <h2 className="text-sm font-semibold text-white">Tendência de Usuários Ativos (Últimas 24h)</h2>
            <p className="text-[11px] text-slate-400">
              Sessões ativas e acessos registrados pelos resolvedores GraphQL nas últimas 24 horas.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono tabular-nums text-slate-400">
          <span>
            Atual: <strong className="text-white">{currentUsers}</strong>
          </span>
          <span aria-hidden="true">·</span>
          <span>
            Pico 24h: <strong className="text-[#F6821F]">{peakUsers}</strong>
          </span>
          {diagnostics && (
            <>
              <span aria-hidden="true">·</span>
              <span className={diagnostics.cacheStatus === 'HIT' ? 'text-emerald-400' : 'text-amber-400'}>
                CF:{diagnostics.cacheStatus}
              </span>
              <span aria-hidden="true">·</span>
              <span>{diagnostics.durationMs.toFixed(1)}ms</span>
              <span aria-hidden="true">·</span>
              <span>SQL:{diagnostics.sqliteQueriesCount}</span>
            </>
          )}
        </div>
      </div>

      <div ref={containerRef} className="relative w-full">
        <svg ref={svgRef} width={width} height={220} className="w-full overflow-visible block" />

        {hovered && (
          <div
            style={{
              left: Math.min(Math.max(12, hovered.x + 12), Math.max(12, width - 190)),
              top: Math.max(8, hovered.y - 44),
            }}
            className="pointer-events-none absolute z-10 bg-[#090D16]/95 border border-slate-700 rounded-md px-3 py-2 text-[11px] font-mono tabular-nums shadow-xl space-y-0.5"
          >
            <div className="text-slate-400">{hovered.point.label}</div>
            <div className="text-white">
              Usuários ativos: <span className="text-[#F6821F] font-semibold">{hovered.point.activeUsers}</span>
            </div>
            <div className="text-slate-300">Sessões ativas: {hovered.point.activeSessions}</div>
            <div className="text-slate-400">Eventos GraphQL/Auth: {hovered.point.eventsCount}</div>
          </div>
        )}
      </div>
    </section>
  );
};

interface HttpStatusWidgetProps {
  data: HttpStatusSystemRow[];
}

const HttpStatusDistributionWidget: React.FC<HttpStatusWidgetProps> = ({ data }) => {
  const totals = useMemo(() => {
    return data.reduce(
      (acc, row) => ({
        s2xx: acc.s2xx + row.s2xx,
        s4xx: acc.s4xx + row.s4xx,
        s5xx: acc.s5xx + row.s5xx,
      }),
      { s2xx: 0, s4xx: 0, s5xx: 0 }
    );
  }, [data]);

  return (
    <section
      aria-label="Distribuição de Códigos HTTP (2xx, 4xx, 5xx) nas Últimas 24 Horas"
      className="bg-[#111827] border border-slate-800/90 rounded-lg p-5 space-y-4"
    >
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2.5">
          <ServerCrash className="w-4 h-4 text-[#F6821F]" />
          <div>
            <h2 className="text-sm font-semibold text-white">Códigos HTTP por Sistema (Últimas 24h)</h2>
            <p className="text-[11px] text-slate-400">
              Distribuição de respostas 2xx, 4xx e 5xx entre todos os sistemas monitorados.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono tabular-nums text-slate-400">
          <span>
            2xx: <strong className="text-emerald-400">{totals.s2xx}</strong>
          </span>
          <span aria-hidden="true">·</span>
          <span>
            4xx: <strong className="text-[#F6821F]">{totals.s4xx}</strong>
          </span>
          <span aria-hidden="true">·</span>
          <span>
            5xx: <strong className="text-red-400">{totals.s5xx}</strong>
          </span>
        </div>
      </div>

      <div className="w-full h-[220px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 10, right: 16, left: -12, bottom: 4 }}>
            <CartesianGrid stroke="rgba(148, 163, 184, 0.1)" strokeDasharray="3 3" vertical={false} />
            <XAxis
              dataKey="systemSlug"
              tick={{ fill: '#94a3b8', fontSize: 10, fontFamily: '"JetBrains Mono", monospace' }}
              axisLine={{ stroke: 'rgba(148, 163, 184, 0.2)' }}
              tickLine={{ stroke: 'rgba(148, 163, 184, 0.2)' }}
            />
            <YAxis
              allowDecimals={false}
              tick={{ fill: '#94a3b8', fontSize: 10, fontFamily: '"JetBrains Mono", monospace' }}
              axisLine={{ stroke: 'rgba(148, 163, 184, 0.2)' }}
              tickLine={{ stroke: 'rgba(148, 163, 184, 0.2)' }}
            />
            <Tooltip
              cursor={{ fill: 'rgba(148, 163, 184, 0.06)' }}
              contentStyle={{
                backgroundColor: '#090D16',
                borderColor: '#334155',
                borderRadius: '0.375rem',
                fontSize: '11px',
                fontFamily: '"JetBrains Mono", monospace',
                color: '#f1f5f9',
              }}
              labelFormatter={(_label, payload) => {
                const row = payload?.[0]?.payload as HttpStatusSystemRow | undefined;
                return row ? `${row.systemName} (${row.systemSlug})` : String(_label);
              }}
            />
            <Legend
              wrapperStyle={{
                fontSize: '11px',
                fontFamily: '"JetBrains Mono", monospace',
                paddingTop: '4px',
              }}
            />
            <Bar dataKey="s2xx" name="2xx Sucesso" stackId="http" fill="#10b981" />
            <Bar dataKey="s4xx" name="4xx Negado" stackId="http" fill="#F6821F" />
            <Bar dataKey="s5xx" name="5xx Erro" stackId="http" fill="#ef4444" radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
};

interface RecentAlertsListProps {
  alerts: AuditLog[];
  unreadIds: Set<string>;
  sseConnected: boolean;
  refreshIntervalMs: RefreshIntervalOption;
  onMarkAllRead: () => void;
}

function isSecurityAlertLog(log: Pick<AuditLog, 'status' | 'action'>): boolean {
  return (
    log.status === 'denied' ||
    log.status === 'error' ||
    /AUTH_LOGIN_FAILED|AUTH_MFA_VERIFY_FAILED|MFA_.*FAILED|UNAUTHORIZED|FORBIDDEN|DENIED|LOCKED/i.test(
      log.action
    )
  );
}

function classifyAlertLabel(action: string): { title: string; tone: 'amber' | 'red' } {
  if (/MFA/i.test(action)) {
    return { title: 'Falha de 2FA', tone: 'amber' };
  }
  if (/LOGIN|AUTH/i.test(action)) {
    return { title: 'Tentativa de Acesso Não Autorizada', tone: 'red' };
  }
  return { title: 'Acesso Negado (RBAC / Política)', tone: 'amber' };
}

const RecentAlertsList: React.FC<RecentAlertsListProps> = ({
  alerts,
  unreadIds,
  sseConnected,
  refreshIntervalMs,
  onMarkAllRead,
}) => {
  const [inspectingAlert, setInspectingAlert] = useState<AuditLog | null>(null);
  const pollingLabel =
    refreshIntervalMs === 0
      ? 'Polling desativado'
      : refreshIntervalMs === 60000
        ? 'Polling 1min'
        : `Polling ${refreshIntervalMs / 1000}s`;

  return (
    <section
      aria-label="Alertas Recentes de Segurança"
      className="bg-[#111827] border border-slate-800/90 rounded-lg overflow-hidden"
    >
      <div className="px-5 py-3.5 border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <AlertOctagon
            className={`w-4 h-4 ${alerts.length > 0 ? 'text-amber-400' : 'text-slate-400'}`}
          />
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-white">Alertas Recentes</h2>
              {unreadIds.size > 0 && (
                <span className="text-[11px] font-mono tabular-nums text-amber-400">
                  · {unreadIds.size} novo{unreadIds.size > 1 ? 's' : ''}
                </span>
              )}
            </div>
            <p className="text-[11px] text-slate-400">
              Monitoramento em tempo real de tentativas de acesso não autorizadas e falhas de autenticação 2FA.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
          <span>{sseConnected ? `SSE tempo real · ${pollingLabel}` : pollingLabel}</span>
          {unreadIds.size > 0 && (
            <button
              type="button"
              onClick={onMarkAllRead}
              className="flex items-center gap-1 px-2.5 py-1 text-xs font-sans font-medium bg-[#090D16] border border-slate-700 hover:border-slate-500 text-slate-200 rounded transition-colors"
            >
              <CheckCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>Marcar como lidos</span>
            </button>
          )}
        </div>
      </div>

      {alerts.length === 0 ? (
        <div className="px-5 py-6 text-center text-xs text-slate-500">
          Nenhuma tentativa de acesso não autorizada ou falha de 2FA detectada nas últimas horas.
        </div>
      ) : (
        <div className="divide-y divide-slate-800/60 max-h-72 overflow-y-auto">
          {alerts.slice(0, 15).map((alert) => {
            const meta = classifyAlertLabel(alert.action);
            const isUnread = unreadIds.has(alert.id);
            return (
              <div
                key={alert.id}
                onClick={() => setInspectingAlert(alert)}
                className={`px-5 py-3 flex flex-wrap items-center justify-between gap-3 cursor-pointer transition-colors ${
                  isUnread ? 'bg-amber-950/20 hover:bg-amber-950/30' : 'hover:bg-slate-800/35'
                }`}
              >
                <div className="min-w-0 space-y-0.5">
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <span
                      className={`font-semibold ${
                        meta.tone === 'red' ? 'text-red-400' : 'text-amber-400'
                      }`}
                    >
                      {meta.title}
                    </span>
                    <span className="text-slate-500" aria-hidden="true">
                      ·
                    </span>
                    <span className="font-mono text-slate-200">{alert.action}</span>
                    {isUnread && (
                      <span className="font-mono text-[11px] text-amber-300">· NOVO</span>
                    )}
                  </div>
                  <div className="text-[11px] font-mono text-slate-400 truncate">
                    Ator {alert.actorMasked} · IP {alert.ipMasked} · Sistema {alert.systemSlug || 'global'} · Trace{' '}
                    {alert.traceId}
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <span className="text-[11px] font-mono tabular-nums text-slate-400">
                    {new Date(alert.createdAt).toLocaleTimeString('pt-BR')}
                  </span>
                  <button
                    type="button"
                    onClick={(ev) => {
                      ev.stopPropagation();
                      setInspectingAlert(alert);
                    }}
                    title="Inspecionar Alerta"
                    className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
                  >
                    <Eye className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Popup Detail Inspector for Security Alert */}
      {inspectingAlert && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="max-w-xl w-full bg-[#111827] border border-slate-700 rounded-lg p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="font-display text-base font-semibold text-white">
                  Alerta de Segurança · <span className="font-mono">{inspectingAlert.action}</span>
                </h3>
                <p className="text-xs font-mono text-slate-400 mt-0.5">
                  {new Date(inspectingAlert.createdAt).toLocaleString('pt-BR')} · Trace {inspectingAlert.traceId}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setInspectingAlert(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <pre className="bg-[#090D16] border border-slate-800 rounded-md p-3.5 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-80 leading-relaxed">
              {JSON.stringify(
                {
                  ...inspectingAlert,
                  details: (() => {
                    try {
                      return JSON.parse(inspectingAlert.detailsJson);
                    } catch {
                      return inspectingAlert.detailsJson;
                    }
                  })(),
                },
                null,
                2
              )}
            </pre>

            <div className="flex justify-end">
              <button
                type="button"
                onClick={() => setInspectingAlert(null)}
                className="px-4 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-white rounded-md"
              >
                Fechar
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
};

export const OverviewTelemetry: React.FC<OverviewTelemetryProps> = ({ token, onNotify }) => {
  const [metrics, setMetrics] = useState<EdgeMetrics | null>(null);
  const [keyStats, setKeyStats] = useState<KeyStatsState | null>(null);
  const [systemsSnapshot, setSystemsSnapshot] = useState<Array<Pick<IamSystem, 'id' | 'name' | 'slug'>>>([]);
  const [usersSnapshot, setUsersSnapshot] = useState<IamUser[]>([]);
  const [logsSnapshot, setLogsSnapshot] = useState<AuditLog[]>([]);
  const [recentAlerts, setRecentAlerts] = useState<AuditLog[]>([]);
  const [healthHistory, setHealthHistory] = useState<SystemHealthEvent[]>([]);
  const [unreadAlertIds, setUnreadAlertIds] = useState<Set<string>>(new Set());
  const [sseConnected, setSseConnected] = useState(false);
  const [lastDiag, setLastDiag] = useState<DiagnosticHeaders | null>(null);
  const [refreshTick, setRefreshTick] = useState(0);
  const [refreshIntervalMs, setRefreshIntervalMs] = useState<RefreshIntervalOption>(10000);
  const seenAlertIdsRef = useRef<Set<string>>(new Set());
  const initialAlertsLoadedRef = useRef(false);
  const onNotifyRef = useRef(onNotify);
  onNotifyRef.current = onNotify;

  const computeWarningsFromLogs = (logs: Array<Pick<AuditLog, 'status' | 'action'>>) => {
    let deniedCount = 0;
    let errorCount = 0;
    let securityAlertCount = 0;

    for (const log of logs) {
      if (log.status === 'denied') deniedCount += 1;
      if (log.status === 'error') errorCount += 1;
      const isWarningAction =
        log.status !== 'success' || /FAILED|LOCKED|REVOKED|DENIED/i.test(log.action);
      if (isWarningAction) securityAlertCount += 1;
    }
    return { securityAlertCount, deniedCount, errorCount };
  };

  const loadData = useCallback(async () => {
    try {
      const { data: baseData, diagnostics: baseDiag } = await gqlRequest<{
        edgeMetrics: EdgeMetrics;
        complianceSummary: ComplianceSummary;
        systems: Array<Pick<IamSystem, 'id' | 'name' | 'slug'>>;
        me: IamUser | null;
        systemHealthHistory: SystemHealthEvent[];
      }>({
        token,
        query: OVERVIEW_BASE_QUERY,
        operationName: 'OverviewBaseTelemetry',
      });
      setMetrics(baseData.edgeMetrics);
      setSystemsSnapshot(baseData.systems || []);
      setHealthHistory(baseData.systemHealthHistory || []);
      setLastDiag(baseDiag);

      const nowMs = Date.now();
      let activeUsers = Math.max(
        0,
        baseData.complianceSummary.totalUsers - baseData.complianceSummary.anonymizedUsers
      );
      let validTokens = 0;
      let revokedOrExpiredTokens = 0;
      let recentWarnings = 0;
      let deniedCount = 0;
      let errorCount = 0;

      try {
        const { data: adminData, diagnostics: adminDiag } = await gqlRequest<{
          users: IamUser[];
          auditLogs: AuditLog[];
        }>({
          token,
          query: OVERVIEW_ADMIN_STATS_QUERY,
          operationName: 'OverviewAdminKeyStats',
        });
        setLastDiag(adminDiag);
        setUsersSnapshot(adminData.users);
        setLogsSnapshot(adminData.auditLogs);

        const extractedAlerts = adminData.auditLogs.filter(isSecurityAlertLog);
        setRecentAlerts(extractedAlerts);

        if (!initialAlertsLoadedRef.current) {
          for (const a of extractedAlerts) {
            seenAlertIdsRef.current.add(a.id);
          }
          initialAlertsLoadedRef.current = true;
        } else {
          const newlyDetected = extractedAlerts.filter((a) => !seenAlertIdsRef.current.has(a.id));
          if (newlyDetected.length > 0) {
            for (const a of newlyDetected) {
              seenAlertIdsRef.current.add(a.id);
            }
            setUnreadAlertIds((prev) => {
              const next = new Set(prev);
              for (const a of newlyDetected) next.add(a.id);
              return next;
            });
            const newest = newlyDetected[0];
            const meta = classifyAlertLabel(newest.action);
            onNotifyRef.current(
              `Alerta em tempo real: ${meta.title} (${newest.actorMasked} · ${newest.ipMasked})`,
              'warning'
            );
          }
        }

        activeUsers = adminData.users.filter((u) => u.status === 'active').length;
        for (const u of adminData.users) {
          for (const s of u.sessions || []) {
            if (!s.revokedAt && Date.parse(s.expiresAt) > nowMs) {
              validTokens += 1;
            } else {
              revokedOrExpiredTokens += 1;
            }
          }
        }
        const warnSummary = computeWarningsFromLogs(adminData.auditLogs);
        recentWarnings = warnSummary.securityAlertCount;
        deniedCount = warnSummary.deniedCount;
        errorCount = warnSummary.errorCount;
      } catch {
        if (baseData.me) {
          setUsersSnapshot([baseData.me]);
        }
        for (const s of baseData.me?.sessions || []) {
          if (!s.revokedAt && Date.parse(s.expiresAt) > nowMs) {
            validTokens += 1;
          } else {
            revokedOrExpiredTokens += 1;
          }
        }
      }

      setKeyStats({
        activeUsers,
        totalUsers: baseData.complianceSummary.totalUsers,
        mfaAdoptedUsers: baseData.complianceSummary.mfaAdoptedUsers,
        validTokens,
        revokedOrExpiredTokens,
        recentWarnings,
        deniedCount,
        errorCount,
      });
    } catch (err) {
      onNotifyRef.current(err instanceof Error ? err.message : 'Erro ao carregar telemetria GraphQL.', 'error');
    }
  }, [token]);

  useEffect(() => {
    void loadData();

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

        if (isSecurityAlertLog(mapped) && !seenAlertIdsRef.current.has(mapped.id)) {
          seenAlertIdsRef.current.add(mapped.id);
          setRecentAlerts((prev) => [mapped, ...prev.slice(0, 49)]);
          setUnreadAlertIds((prev) => {
            const next = new Set(prev);
            next.add(mapped.id);
            return next;
          });
          const meta = classifyAlertLabel(mapped.action);
          onNotifyRef.current(
            `Alerta em tempo real: ${meta.title} (${mapped.actorMasked} · ${mapped.ipMasked})`,
            'warning'
          );
        }
      } catch {
        // ignore malformed stream payload
      }
    });
    es.addEventListener('health_transition', (ev) => {
      try {
        const raw = JSON.parse((ev as MessageEvent).data) as {
          id: string;
          previous_status: 'healthy' | 'degraded' | 'critical' | null;
          new_status: 'healthy' | 'degraded' | 'critical';
          avg_latency_ms: number;
          max_latency_ms: number;
          sample_count: number;
          error_count: number;
          reason: string;
          created_at: string;
        };
        const mapped: SystemHealthEvent = {
          id: raw.id,
          previousStatus: raw.previous_status,
          newStatus: raw.new_status,
          avgLatencyMs: raw.avg_latency_ms,
          maxLatencyMs: raw.max_latency_ms,
          sampleCount: raw.sample_count,
          errorCount: raw.error_count,
          reason: raw.reason,
          createdAt: raw.created_at,
        };
        setHealthHistory((prev) =>
          prev.some((item) => item.id === mapped.id) ? prev : [mapped, ...prev].slice(0, 50)
        );
      } catch {
        // ignore malformed health_transition payload
      }
    });
    es.onerror = () => setSseConnected(false);

    return () => {
      es.close();
    };
  }, [loadData]);

  useEffect(() => {
    if (refreshIntervalMs <= 0) return;
    const pollTimer = window.setInterval(() => {
      void loadData();
    }, refreshIntervalMs);
    return () => window.clearInterval(pollTimer);
  }, [refreshIntervalMs, loadData]);

  const handleLogsUpdated = useCallback((updatedLogs: AuditLog[]) => {
    setLogsSnapshot(updatedLogs);
    setRecentAlerts(updatedLogs.filter(isSecurityAlertLog));
    const warnSummary = computeWarningsFromLogs(updatedLogs);
    setKeyStats((prev) =>
      prev
        ? {
            ...prev,
            recentWarnings: warnSummary.securityAlertCount,
            deniedCount: warnSummary.deniedCount,
            errorCount: warnSummary.errorCount,
          }
        : prev
    );
  }, []);

  // Build 24 hourly buckets from GraphQL users, sessions, and auditLogs diagnostics
  const activeUsers24hTrend = useMemo<HourlyTrendPoint[]>(() => {
    const now = new Date();
    const currentHourStart = new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate(),
      now.getHours(),
      0,
      0,
      0
    ).getTime();

    const buckets: HourlyTrendPoint[] = [];
    for (let offset = 23; offset >= 0; offset -= 1) {
      const startMs = currentHourStart - offset * 3600 * 1000;
      const endMs = startMs + 3600 * 1000;
      const hourDate = new Date(startMs);
      const label = d3.timeFormat('%d/%m %H:00')(hourDate);

      const distinctActors = new Set<string>();
      let activeSessions = 0;
      let eventsCount = 0;

      for (const user of usersSnapshot) {
        let userActiveInBucket = false;
        for (const ses of user.sessions || []) {
          const sesStart = Date.parse(ses.createdAt);
          const sesEnd = ses.revokedAt ? Date.parse(ses.revokedAt) : Date.parse(ses.expiresAt);
          if (!Number.isNaN(sesStart) && !Number.isNaN(sesEnd) && sesStart <= endMs && sesEnd >= startMs) {
            activeSessions += 1;
            userActiveInBucket = true;
          }
        }
        if (user.lastLoginAt) {
          const loginMs = Date.parse(user.lastLoginAt);
          if (!Number.isNaN(loginMs) && loginMs >= startMs && loginMs <= endMs) {
            userActiveInBucket = true;
          }
        }
        if (userActiveInBucket) {
          distinctActors.add(user.id);
        }
      }

      for (const log of logsSnapshot) {
        const logMs = Date.parse(log.createdAt);
        if (!Number.isNaN(logMs) && logMs >= startMs && logMs <= endMs) {
          eventsCount += 1;
          if (log.actorHash && log.actorHash !== 'anonymous') {
            distinctActors.add(log.actorHash);
          }
        }
      }

      buckets.push({
        hourDate,
        label,
        activeUsers: distinctActors.size,
        activeSessions,
        eventsCount,
      });
    }

    return buckets;
  }, [usersSnapshot, logsSnapshot]);

  // Compute HTTP Status Code (2xx, 4xx, 5xx) distribution across all monitored systems over past 24h
  const httpStatusBySystem24h = useMemo<HttpStatusSystemRow[]>(() => {
    const cutoffMs = Date.now() - 24 * 3600 * 1000;
    const map = new Map<string, HttpStatusSystemRow>();

    for (const sys of systemsSnapshot) {
      map.set(sys.slug, {
        systemName: sys.name,
        systemSlug: sys.slug,
        s2xx: 0,
        s4xx: 0,
        s5xx: 0,
        total: 0,
      });
    }

    for (const log of logsSnapshot) {
      const logMs = Date.parse(log.createdAt);
      if (Number.isNaN(logMs) || logMs < cutoffMs) continue;

      const slug = log.systemSlug || 'global';
      if (!map.has(slug)) {
        map.set(slug, {
          systemName: slug === 'global' ? 'Smarties Secure Gate Global' : slug,
          systemSlug: slug,
          s2xx: 0,
          s4xx: 0,
          s5xx: 0,
          total: 0,
        });
      }
      const entry = map.get(slug)!;
      if (log.status === 'success') entry.s2xx += 1;
      else if (log.status === 'denied') entry.s4xx += 1;
      else entry.s5xx += 1;
      entry.total += 1;
    }

    return Array.from(map.values());
  }, [systemsSnapshot, logsSnapshot]);

  const handlePurgeCache = async () => {
    try {
      const { data } = await gqlRequest<{ purgeEdgeCache: number }>({
        token,
        query: `mutation PurgeAll { purgeEdgeCache }`,
        operationName: 'PurgeAll',
      });
      onNotify(`Cache de borda invalidado (${data.purgeEdgeCache} entradas removidas).`, 'success');
      setRefreshTick((t) => t + 1);
      void loadData();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Sem permissão para purgar cache.', 'error');
    }
  };

  const handleRefreshAll = () => {
    setRefreshTick((t) => t + 1);
    void loadData();
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-xl font-semibold text-white">Visão Geral</h1>
          <p className="text-xs text-slate-400 mt-1">
            Estatísticas-chave, tendência de usuários ativos em 24h, métricas na borda e auditoria de acesso em tempo real.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <div className="flex items-center gap-1.5 bg-[#111827] border border-slate-700/80 rounded-md px-2.5 py-1.5">
            <Timer className="w-3.5 h-3.5 text-[#F6821F] shrink-0" />
            <label htmlFor="overview-refresh-interval" className="text-[11px] text-slate-400 whitespace-nowrap">
              Atualização:
            </label>
            <select
              id="overview-refresh-interval"
              aria-label="Intervalo de atualização automática"
              value={refreshIntervalMs}
              onChange={(e) => setRefreshIntervalMs(Number(e.target.value) as RefreshIntervalOption)}
              className="bg-transparent text-xs font-mono text-slate-100 focus:outline-none cursor-pointer"
            >
              <option value={10000} className="bg-[#090D16]">10s</option>
              <option value={30000} className="bg-[#090D16]">30s</option>
              <option value={60000} className="bg-[#090D16]">1min</option>
              <option value={0} className="bg-[#090D16]">Desativado</option>
            </select>
          </div>
          <button
            type="button"
            onClick={handleRefreshAll}
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

      {/* Key Statistics Widget */}
      <section aria-label="Estatísticas-Chave" className="bg-[#111827] border border-slate-800/90 rounded-lg p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
          <div>
            <h2 className="text-sm font-semibold text-white">Estatísticas-Chave</h2>
            <p className="text-[11px] text-slate-400">
              Contagem ao vivo obtida via GraphQL (DataLoader em lote) e stream de auditoria.
            </p>
          </div>
          <span className="text-[11px] font-mono text-slate-400">Atualização ao vivo</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-[#090D16] border border-slate-800 rounded-md p-4 space-y-1.5">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Usuários Ativos</span>
              <Users className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="font-mono tabular-nums text-2xl font-semibold text-white">
              {keyStats ? keyStats.activeUsers : '—'}
            </div>
            <div className="text-[11px] font-mono tabular-nums text-slate-400">
              {keyStats
                ? `${keyStats.totalUsers} cadastrados · ${keyStats.mfaAdoptedUsers} com 2FA ativo`
                : 'Consultando GraphQL...'}
            </div>
          </div>

          <div className="bg-[#090D16] border border-slate-800 rounded-md p-4 space-y-1.5">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Tokens JWT Válidos</span>
              <KeyRound className="w-4 h-4 text-[#F6821F]" />
            </div>
            <div className="font-mono tabular-nums text-2xl font-semibold text-white">
              {keyStats ? keyStats.validTokens : '—'}
            </div>
            <div className="text-[11px] font-mono tabular-nums text-slate-400">
              {keyStats
                ? `${keyStats.revokedOrExpiredTokens} revogados ou expirados · sessões ativas`
                : 'Consultando GraphQL...'}
            </div>
          </div>

          <div className="bg-[#090D16] border border-slate-800 rounded-md p-4 space-y-1.5">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Alertas de Segurança Recentes</span>
              <ShieldAlert
                className={`w-4 h-4 ${
                  keyStats && keyStats.recentWarnings > 0 ? 'text-amber-400' : 'text-slate-400'
                }`}
              />
            </div>
            <div className="font-mono tabular-nums text-2xl font-semibold text-white">
              {keyStats ? keyStats.recentWarnings : '—'}
            </div>
            <div className="text-[11px] font-mono tabular-nums text-slate-400">
              {keyStats
                ? `${keyStats.deniedCount} negados · ${keyStats.errorCount} falhas nos últimos eventos`
                : 'Consultando GraphQL...'}
            </div>
          </div>
        </div>
      </section>

      {/* D3 24-Hour Active Users Trend & Recharts HTTP Status Code Distribution */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <ActiveUsersTrendChart data={activeUsers24hTrend} diagnostics={lastDiag} />
        <HttpStatusDistributionWidget data={httpStatusBySystem24h} />
      </div>

      {/* Edge & SQLite Performance KPI Strip */}
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
            {metrics
              ? `${metrics.cacheHits} HIT · ${metrics.cacheMisses} MISS · ${metrics.cachedEntriesCount} em RAM`
              : 'Carregando...'}
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
            {metrics
              ? `Média HIT ${metrics.avgHitLatencyMs}ms · MISS ${metrics.avgMissLatencyMs}ms`
              : 'Carregando...'}
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
            {metrics
              ? `${metrics.sqliteTotalReads} leituras · ${metrics.sqliteTotalWrites} gravações`
              : 'Carregando...'}
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800/90 rounded-lg p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Versões KV e Lotes de Auditoria</span>
            <Radio className="w-3.5 h-3.5 text-slate-400" />
          </div>
          <div className="font-mono tabular-nums text-2xl font-semibold text-white">
            {metrics ? `${metrics.kvVersionReads}` : '—'}
          </div>
          <div className="text-[11px] font-mono tabular-nums text-slate-400">
            {metrics
              ? `${metrics.batchedAuditFlushes} lotes gravados · ${metrics.activeSseStreams} streams SSE`
              : 'Carregando...'}
          </div>
        </div>
      </div>

      {/* Historical Log of System Health Status Transitions */}
      <HealthHistoryPanel events={healthHistory} sseConnected={sseConnected} />

      {/* Recent Security Alerts List (SSE + Polling) */}
      <RecentAlertsList
        alerts={recentAlerts}
        unreadIds={unreadAlertIds}
        sseConnected={sseConnected}
        refreshIntervalMs={refreshIntervalMs}
        onMarkAllRead={() => setUnreadAlertIds(new Set())}
      />

      {/* Searchable & Filterable Audit Logs */}
      <AuditLogs
        token={token}
        onNotify={onNotify}
        refreshSignal={refreshTick}
        onLogsUpdated={handleLogsUpdated}
      />
    </div>
  );
};
