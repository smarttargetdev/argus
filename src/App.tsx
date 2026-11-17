import React, { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AppWindow,
  Users,
  Shield,
  Globe,
  Code2,
  FileCheck2,
  UserCircle2,
  LogOut,
  CheckCircle2,
  Clock,
  X,
} from 'lucide-react';
import { AuthGate } from './components/AuthGate';
import { OverviewTelemetry } from './components/OverviewTelemetry';
import { SystemsManager } from './components/SystemsManager';
import { UsersManager } from './components/UsersManager';
import { RbacClaimsManager } from './components/RbacClaimsManager';
import { IdpAndOAuthSandbox } from './components/IdpAndOAuthSandbox';
import { GraphqlAndCloudflare } from './components/GraphqlAndCloudflare';
import { ProfileAndCompliance } from './components/ProfileAndCompliance';
import { subscribeDiagnostics } from './lib/graphqlClient';
import { useSessionExpiration } from './hooks/useSessionExpiration';
import type { AuthSessionState, DiagnosticHeaders } from './types/iam';

type NavTab =
  | 'overview'
  | 'systems'
  | 'users'
  | 'rbac'
  | 'idps'
  | 'graphql'
  | 'compliance'
  | 'profile';

const SESSION_STORAGE_KEY = 'vektor_iam_session_v1';

const NAV_ITEMS: Array<{
  id: NavTab;
  label: string;
  group: 'admin' | 'infra' | 'self';
  icon: React.ComponentType<{ className?: string }>;
}> = [
  { id: 'overview', label: 'Visão Geral', group: 'admin', icon: Activity },
  { id: 'systems', label: 'Sistemas', group: 'admin', icon: AppWindow },
  { id: 'users', label: 'Usuários', group: 'admin', icon: Users },
  { id: 'rbac', label: 'Permissões', group: 'admin', icon: Shield },
  { id: 'idps', label: 'Provedores', group: 'infra', icon: Globe },
  { id: 'graphql', label: 'Infraestrutura', group: 'infra', icon: Code2 },
  { id: 'compliance', label: 'Conformidade', group: 'self', icon: FileCheck2 },
  { id: 'profile', label: 'Perfil', group: 'self', icon: UserCircle2 },
];

export default function App() {
  const [session, setSession] = useState<AuthSessionState | null>(() => {
    try {
      const saved = localStorage.getItem(SESSION_STORAGE_KEY);
      if (!saved) return null;
      const parsed = JSON.parse(saved) as AuthSessionState;
      if (new Date(parsed.expiresAt).getTime() <= Date.now()) {
        localStorage.removeItem(SESSION_STORAGE_KEY);
        return null;
      }
      return parsed;
    } catch {
      return null;
    }
  });

  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [toast, setToast] = useState<string | null>(null);
  const [lastDiag, setLastDiag] = useState<DiagnosticHeaders | null>(null);
  const [refreshTick, setRefreshTick] = useState(0);

  useEffect(() => {
    return subscribeDiagnostics((diag) => {
      setLastDiag(diag);
    });
  }, []);

  const handleLogout = useCallback(() => {
    setSession(null);
    localStorage.removeItem(SESSION_STORAGE_KEY);
  }, []);

  const { formattedRemaining, isExpiringSoon, showWarning, dismissWarning } = useSessionExpiration(
    session?.expiresAt ?? null,
    handleLogout
  );

  const notify = (msg: string) => {
    if (msg === 'UNAUTHENTICATED') {
      handleLogout();
      return;
    }
    setToast(msg);
    window.setTimeout(() => {
      setToast((curr) => (curr === msg ? null : curr));
    }, 4500);
  };

  const handleAuthenticated = (nextSession: AuthSessionState) => {
    setSession(nextSession);
    localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(nextSession));
    const hasAdmin =
      nextSession.user.roles.includes('super_admin') ||
      nextSession.user.permissions.includes('iam:users:read') ||
      nextSession.user.permissions.includes('iam:audit:read');
    setActiveTab(hasAdmin ? 'overview' : 'profile');
  };

  if (!session) {
    return <AuthGate onAuthenticated={handleAuthenticated} />;
  }

  const activeNav = NAV_ITEMS.find((i) => i.id === activeTab);

  return (
    <div className="min-h-screen bg-[#090D16] text-slate-100 flex">
      {/* Fixed Sidebar (248px) */}
      <aside className="w-[248px] shrink-0 bg-[#0D131F] border-r border-slate-800/80 flex flex-col justify-between">
        <div>
          <div className="h-14 px-5 border-b border-slate-800/80 flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-md bg-[#F6821F]/15 border border-[#F6821F]/40 flex items-center justify-center text-[#F6821F]">
              <Shield className="w-3.5 h-3.5" />
            </div>
            <span className="font-display text-sm font-semibold tracking-tight text-white whitespace-nowrap">
              Smarties Gate
            </span>
          </div>

          <nav className="p-3 space-y-5">
            <div>
              <div className="px-2.5 pb-1.5 text-[11px] font-medium text-slate-500">Administração GraphQL</div>
              <div className="space-y-0.5">
                {NAV_ITEMS.filter((i) => i.group === 'admin').map((item) => {
                  const Icon = item.icon;
                  const isActive = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => setActiveTab(item.id)}
                      className={`w-full flex items-center gap-2.5 px-2.5 py-2 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
                        isActive
                          ? 'bg-[#F6821F]/15 text-white border border-[#F6821F]/40'
                          : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/40 border border-transparent'
                      }`}
                    >
                      <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-[#F6821F]' : 'text-slate-400'}`} />
                      <span className="truncate">{item.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            <div>
              <div className="px-2.5 pb-1.5 text-[11px] font-medium text-slate-500">Borda, OAuth & D1</div>
              <div className="space-y-0.5">
                {NAV_ITEMS.filter((i) => i.group === 'infra').map((item) => {
                  const Icon = item.icon;
                  const isActive = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => setActiveTab(item.id)}
                      className={`w-full flex items-center gap-2.5 px-2.5 py-2 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
                        isActive
                          ? 'bg-[#F6821F]/15 text-white border border-[#F6821F]/40'
                          : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/40 border border-transparent'
                      }`}
                    >
                      <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-[#F6821F]' : 'text-slate-400'}`} />
                      <span className="truncate">{item.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            <div>
              <div className="px-2.5 pb-1.5 text-[11px] font-medium text-slate-500">Titular & Privacidade</div>
              <div className="space-y-0.5">
                {NAV_ITEMS.filter((i) => i.group === 'self').map((item) => {
                  const Icon = item.icon;
                  const isActive = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => setActiveTab(item.id)}
                      className={`w-full flex items-center gap-2.5 px-2.5 py-2 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
                        isActive
                          ? 'bg-[#F6821F]/15 text-white border border-[#F6821F]/40'
                          : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/40 border border-transparent'
                      }`}
                    >
                      <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-[#F6821F]' : 'text-slate-400'}`} />
                      <span className="truncate">{item.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          </nav>
        </div>

        <div className="p-4 border-t border-slate-800/80 space-y-2 text-[11px]">
          <div className="text-slate-200 font-medium truncate">{session.user.displayName}</div>
          <div className="font-mono text-slate-400 truncate">{session.user.email}</div>
          <div className="font-mono text-slate-500 truncate">
            {session.system.slug} · {session.user.roles.join(', ') || 'member'}
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Top Bar (Clean Breadcrumb + Last GraphQL Edge Diagnostic + Session Countdown + Sign Out) */}
        <header className="h-14 px-6 border-b border-slate-800/80 bg-[#090D16] flex items-center justify-between gap-6 shrink-0">
          <div className="flex items-center gap-2 text-xs text-slate-400 whitespace-nowrap truncate">
            <span>Smarties Gate</span>
            <span aria-hidden="true">/</span>
            <span className="font-mono text-slate-300">{session.system.slug}</span>
            <span aria-hidden="true">/</span>
            <span className="text-white font-medium">{activeNav?.label}</span>
          </div>

          <div className="flex items-center gap-4 shrink-0">
            {lastDiag && (
              <div className="hidden xl:flex items-center gap-2 text-[11px] font-mono tabular-nums text-slate-400">
                <span className={lastDiag.cacheStatus === 'HIT' ? 'text-emerald-400' : 'text-amber-400'}>
                  CF:{lastDiag.cacheStatus}
                </span>
                <span aria-hidden="true">·</span>
                <span>{lastDiag.durationMs.toFixed(1)}ms</span>
                <span aria-hidden="true">·</span>
                <span>SQL:{lastDiag.sqliteQueriesCount}</span>
              </div>
            )}
            <div
              className={`hidden md:flex items-center gap-1.5 text-[11px] font-mono tabular-nums ${
                isExpiringSoon ? 'text-amber-400' : 'text-slate-400'
              }`}
              title="Tempo restante do token JWT da sessão"
            >
              <Clock className="w-3 h-3" />
              <span>{formattedRemaining}</span>
            </div>
            <button
              type="button"
              onClick={handleLogout}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-[#111827] hover:bg-slate-800 border border-slate-700/80 text-slate-200 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Encerrar Sessão</span>
            </button>
          </div>
        </header>

        {/* Notification Banner */}
        {toast && (
          <div className="mx-6 mt-4 px-4 py-2.5 rounded-md bg-[#111827] border border-[#F6821F]/50 flex items-center justify-between gap-3 text-xs text-slate-100">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-[#F6821F] shrink-0" />
              <span>{toast}</span>
            </div>
            <button type="button" onClick={() => setToast(null)} className="text-slate-400 hover:text-white">
              Fechar
            </button>
          </div>
        )}

        {/* Active Viewport */}
        <main className="flex-1 p-6 max-w-[1360px] w-full">
          {activeTab === 'overview' && <OverviewTelemetry key={refreshTick} token={session.token} onNotify={notify} />}
          {activeTab === 'systems' && (
            <SystemsManager
              token={session.token}
              onNotify={notify}
              onSystemsChanged={() => setRefreshTick((t) => t + 1)}
            />
          )}
          {activeTab === 'users' && (
            <UsersManager token={session.token} currentUserId={session.user.id} onNotify={notify} />
          )}
          {activeTab === 'rbac' && <RbacClaimsManager token={session.token} onNotify={notify} />}
          {activeTab === 'idps' && <IdpAndOAuthSandbox token={session.token} onNotify={notify} />}
          {activeTab === 'graphql' && <GraphqlAndCloudflare token={session.token} onNotify={notify} />}
          {activeTab === 'compliance' && (
            <ProfileAndCompliance
              token={session.token}
              mode="compliance"
              onNotify={notify}
              onSessionInvalidated={handleLogout}
            />
          )}
          {activeTab === 'profile' && (
            <ProfileAndCompliance
              token={session.token}
              mode="profile"
              onNotify={notify}
              onSessionInvalidated={handleLogout}
            />
          )}
        </main>
      </div>

      {/* Subtle Non-Intrusive Session Expiration Modal Warning (5 min before expiry) */}
      {showWarning && (
        <div
          role="dialog"
          aria-modal="false"
          aria-label="Aviso de expiração de sessão"
          className="fixed bottom-5 right-5 z-50 max-w-sm w-[calc(100vw-2.5rem)] bg-[#111827]/95 backdrop-blur border border-amber-500/50 rounded-lg p-4 shadow-2xl space-y-3"
        >
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-2 text-amber-400">
              <Clock className="w-4 h-4 shrink-0" />
              <h3 className="font-display text-xs font-semibold text-white">Sessão prestes a expirar</h3>
            </div>
            <button
              type="button"
              onClick={dismissWarning}
              aria-label="Fechar aviso"
              className="text-slate-400 hover:text-white"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Seu token JWT expirará em{' '}
            <span className="font-mono tabular-nums font-semibold text-amber-300">{formattedRemaining}</span>.
            Salve alterações pendentes ou reautentique para renovar sua sessão.
          </p>
          <div className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={dismissWarning}
              className="px-3 py-1.5 text-xs text-slate-300 hover:text-white border border-slate-700 rounded-md"
            >
              Continuar
            </button>
            <button
              type="button"
              onClick={handleLogout}
              className="px-3 py-1.5 text-xs font-semibold bg-[#F6821F] hover:bg-[#e27316] text-slate-950 rounded-md"
            >
              Reautenticar
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
