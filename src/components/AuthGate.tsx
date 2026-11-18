import React, { useEffect, useState } from 'react';
import { Shield, KeyRound, Smartphone, Lock, ArrowRight, Globe, AlertCircle, CheckCircle2 } from 'lucide-react';
import type { AuthSessionState, ExecutionEnvironment, PublicPlatformConfig } from '../types/iam';

interface PublicSystemItem {
  id: string;
  name: string;
  slug: string;
  description: string;
  clientId: string;
  jwtTtlSeconds: number;
  signingAlg: string;
  requireMfa: boolean;
  allowedIdps: string[];
  edgeCacheTtl: number;
}

interface PublicIdpItem {
  id: string;
  name: string;
  provider_type: string;
  simulation_mode: number;
}

interface MfaPendingState {
  mfaToken: string;
  availableMethods: string[];
  preferredMethod: string;
  phoneMasked: string | null;
  systemName: string;
}

interface AuthGateProps {
  onAuthenticated: (session: AuthSessionState) => void;
}

export const AuthGate: React.FC<AuthGateProps> = ({ onAuthenticated }) => {
  const [systems, setSystems] = useState<PublicSystemItem[]>([]);
  const [idps, setIdps] = useState<PublicIdpItem[]>([]);
  const [selectedSlug, setSelectedSlug] = useState('vektor-core');
  const [platformName, setPlatformName] = useState('Smarties Secure Gate');
  const [executionEnvironment, setExecutionEnvironment] = useState<ExecutionEnvironment | null>(null);

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const [mfaPending, setMfaPending] = useState<MfaPendingState | null>(null);
  const [mfaMethod, setMfaMethod] = useState<'totp' | 'sms' | 'backup_code'>('totp');
  const [mfaCode, setMfaCode] = useState('');
  const [smsPreview, setSmsPreview] = useState<string | null>(null);

  const [idpModal, setIdpModal] = useState<{ providerType: string; name: string } | null>(null);
  const [idpEmail, setIdpEmail] = useState('');
  const [idpName, setIdpName] = useState('Usuário Federado');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/public/systems')
      .then((r) => r.json())
      .then((data: {
        platformConfig?: PublicPlatformConfig;
        systems?: PublicSystemItem[];
        identityProviders?: PublicIdpItem[];
      }) => {
        setSystems(data.systems || []);
        setIdps(data.identityProviders || []);
        const cfg = data.platformConfig;
        const env: ExecutionEnvironment = cfg?.executionEnvironment || 'Desenvolvimento';
        setExecutionEnvironment(env);
        if (cfg?.platformName) {
          setPlatformName(cfg.platformName);
        }
        if (env === 'Desenvolvimento') {
          setEmail((curr) => curr || 'admin@vektor.iam');
          setPassword((curr) => curr || 'Vektor@2026!');
          setIdpEmail((curr) => curr || 'admin@vektor.iam');
        } else {
          setEmail('');
          setPassword('');
          setIdpEmail('');
        }
      })
      .catch(() => {
        setExecutionEnvironment('Desenvolvimento');
      });

    const handlePopupMessage = (ev: MessageEvent) => {
      if (ev.data?.type === 'VEKTOR_IDP_CALLBACK') {
        setError(null);
      }
    };
    window.addEventListener('message', handlePopupMessage);
    return () => window.removeEventListener('message', handlePopupMessage);
  }, []);

  const currentSystem = systems.find((s) => s.slug === selectedSlug);
  const showDemoPanel = executionEnvironment !== null && executionEnvironment !== 'Produção';

  const handleSubmitCredentials = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSmsPreview(null);

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, systemSlug: selectedSlug }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Falha na autenticação.');
      }

      if (data.requiresMfa) {
        setMfaPending({
          mfaToken: data.mfaToken,
          availableMethods: data.availableMethods,
          preferredMethod: data.preferredMethod,
          phoneMasked: data.phoneMasked,
          systemName: data.system?.name || selectedSlug,
        });
        const pref = data.preferredMethod;
        setMfaMethod(pref === 'sms' || pref === 'totp' || pref === 'backup_code' ? pref : 'totp');
        return;
      }

      onAuthenticated({
        token: data.accessToken,
        expiresAt: data.expiresAt,
        system: data.system,
        user: data.user,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Erro inesperado.');
    } finally {
      setLoading(false);
    }
  };

  const handleSendSmsOtp = async () => {
    if (!mfaPending) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/auth/mfa/send-sms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaToken: mfaPending.mfaToken }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Falha ao enviar SMS OTP.');
      setSmsPreview(data.sandboxCodePreview || null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Erro ao enviar SMS.');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaPending) return;
    setLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mfaToken: mfaPending.mfaToken,
          method: mfaMethod,
          code: mfaCode,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Código 2FA inválido.');

      onAuthenticated({
        token: data.accessToken,
        expiresAt: data.expiresAt,
        system: data.system,
        user: data.user,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Erro na verificação 2FA.');
    } finally {
      setLoading(false);
    }
  };

  const handleTriggerIdp = async (idp: PublicIdpItem) => {
    setError(null);
    try {
      const res = await fetch(`/api/auth/idp/${idp.provider_type}/url`);
      const data = await res.json();
      if (data.simulation) {
        setIdpModal({ providerType: idp.provider_type, name: idp.name });
        return;
      }
      if (data.url) {
        window.open(data.url, 'vektor_idp_oauth', 'width=560,height=680');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Erro ao iniciar IdP externo.');
    }
  };

  const handleConfirmIdpSimulation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!idpModal) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/auth/idp/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          providerType: idpModal.providerType,
          externalEmail: idpEmail,
          externalName: idpName,
          systemSlug: selectedSlug,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Falha na federação externa.');
      setIdpModal(null);

      if (data.requiresMfa) {
        setMfaPending({
          mfaToken: data.mfaToken,
          availableMethods: data.availableMethods,
          preferredMethod: data.preferredMethod,
          phoneMasked: data.phoneMasked,
          systemName: data.system?.name || selectedSlug,
        });
        return;
      }

      onAuthenticated({
        token: data.accessToken,
        expiresAt: data.expiresAt,
        system: data.system,
        user: data.user,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Erro na federação IdP.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#090D16] text-slate-100 flex flex-col justify-between px-6 py-8">
      <header className="max-w-6xl w-full mx-auto flex items-center justify-between gap-8 pb-6 border-b border-slate-800/80">
        <div className="flex items-center gap-3 whitespace-nowrap shrink-0">
          <div className="w-8 h-8 rounded-md bg-[#F6821F]/15 border border-[#F6821F]/40 flex items-center justify-center text-[#F6821F]">
            <Shield className="w-4 h-4" />
          </div>
          <span className="font-display text-lg font-semibold tracking-tight text-white">{platformName}</span>
        </div>
        <div className="hidden sm:flex items-center gap-3 text-xs text-slate-400">
          <span>OAuth 2.0 / OIDC</span>
          <span aria-hidden="true">·</span>
          <span>SQLite WAL / Cloudflare D1</span>
          <span aria-hidden="true">·</span>
          <span>LGPD & GDPR</span>
          {executionEnvironment && (
            <>
              <span aria-hidden="true">·</span>
              <span className={executionEnvironment === 'Produção' ? 'text-amber-400 font-medium' : 'text-slate-300'}>
                {executionEnvironment}
              </span>
            </>
          )}
        </div>
      </header>

      <main
        className={
          showDemoPanel
            ? 'max-w-5xl w-full mx-auto my-auto py-10 grid grid-cols-1 lg:grid-cols-12 gap-8 items-start'
            : 'max-w-xl w-full mx-auto my-auto py-10'
        }
      >
        {/* Unified Identidade Digital Panel */}
        <div
          className={`${
            showDemoPanel ? 'lg:col-span-7' : 'w-full'
          } bg-[#111827] border border-slate-800/90 rounded-lg p-7 sm:p-8 space-y-6`}
        >
          {!mfaPending ? (
            <>
              <div className="space-y-2 pb-5 border-b border-slate-800/80">
                <p className="text-xs font-medium text-[#F6821F]">Controle de Acesso</p>
                <h1 className="font-display text-2xl font-semibold text-white leading-tight [text-wrap:balance]">
                  Identidade Digital
                </h1>
                <p className="text-sm text-slate-400 leading-relaxed">
                  Selecione o sistema e informe as credenciais do usuário para validar a identidade.
                </p>
              </div>

              <form onSubmit={handleSubmitCredentials} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1.5">Sistema</label>
                  <select
                    value={selectedSlug}
                    onChange={(e) => {
                      setSelectedSlug(e.target.value);
                      setMfaPending(null);
                      setError(null);
                    }}
                    className="w-full bg-[#090D16] border border-slate-700/80 rounded-md px-3 py-2.5 text-sm text-slate-100 focus:outline-none focus:border-[#F6821F]"
                  >
                    {systems.map((sys) => (
                      <option key={sys.id} value={sys.slug}>
                        {sys.name} ({sys.slug})
                      </option>
                    ))}
                  </select>
                  {currentSystem && (
                    <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] font-mono tabular-nums text-slate-400">
                      <span>{currentSystem.signingAlg}</span>
                      <span aria-hidden="true">·</span>
                      <span>JWT {currentSystem.jwtTtlSeconds}s</span>
                      <span aria-hidden="true">·</span>
                      <span>Cache {currentSystem.edgeCacheTtl}s</span>
                      <span aria-hidden="true">·</span>
                      <span className={currentSystem.requireMfa ? 'text-amber-400 font-sans font-medium' : 'font-sans'}>
                        {currentSystem.requireMfa ? '2FA Obrigatório' : '2FA Opcional'}
                      </span>
                    </div>
                  )}
                </div>

                {error && (
                  <div className="flex items-start gap-2.5 p-3 rounded-md bg-red-950/40 border border-red-800/60 text-xs text-red-200">
                    <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                    <span>{error}</span>
                  </div>
                )}

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1.5">E-mail corporativo</label>
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="voce@empresa.com"
                    className="w-full bg-[#090D16] border border-slate-700/80 rounded-md px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-[#F6821F]"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1.5">Senha</label>
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full bg-[#090D16] border border-slate-700/80 rounded-md px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-[#F6821F]"
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full flex items-center justify-center gap-2 bg-[#F6821F] hover:bg-[#e27316] disabled:opacity-50 text-slate-950 font-semibold text-sm py-2.5 px-4 rounded-md transition-colors whitespace-nowrap"
                >
                  <span>{loading ? 'Autenticando...' : 'Autenticar e Emitir JWT'}</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </form>

              <div className="pt-6 border-t border-slate-800/80">
                <p className="text-xs font-medium text-slate-400 mb-3">
                  Provedores de Identidade Externos (OAuth 2.0 / OIDC / SAML)
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {idps
                    .filter((idp) => !currentSystem || currentSystem.allowedIdps.includes(idp.provider_type))
                    .map((idp) => (
                      <button
                        key={idp.id}
                        type="button"
                        onClick={() => handleTriggerIdp(idp)}
                        className="flex items-center justify-between gap-2 px-3 py-2.5 rounded-md bg-[#090D16] border border-slate-800 hover:border-slate-600 text-xs text-slate-200 transition-colors"
                      >
                        <span className="flex items-center gap-2 truncate">
                          <Globe className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                          <span className="truncate">{idp.name}</span>
                        </span>
                        <span className="text-[11px] text-slate-500 shrink-0">
                          {idp.simulation_mode ? 'Simulado' : 'Produção'}
                        </span>
                      </button>
                    ))}
                </div>
              </div>
            </>
          ) : (
            /* Post-Login 2FA Gate */
            <div className="space-y-6">
              <div className="flex items-start justify-between gap-4 pb-5 border-b border-slate-800/80">
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-xs font-medium text-[#F6821F]">
                    <Lock className="w-3.5 h-3.5" />
                    <span>Verificação de Dois Fatores (2FA)</span>
                  </div>
                  <h2 className="font-display text-xl font-semibold text-white">
                    Confirme sua identidade para {mfaPending.systemName}
                  </h2>
                  <p className="text-xs text-slate-400">
                    O JWT final será emitido somente após a conclusão deste desafio de segundo fator.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setMfaPending(null);
                    setMfaCode('');
                    setSmsPreview(null);
                    setError(null);
                  }}
                  className="text-xs text-slate-400 hover:text-white underline whitespace-nowrap shrink-0"
                >
                  Voltar
                </button>
              </div>

              {error && (
                <div className="flex items-start gap-2.5 p-3 rounded-md bg-red-950/40 border border-red-800/60 text-xs text-red-200">
                  <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}

              <div className="flex flex-wrap gap-2">
                {mfaPending.availableMethods.includes('totp') && (
                  <button
                    type="button"
                    onClick={() => setMfaMethod('totp')}
                    className={`flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-md border transition-colors ${
                      mfaMethod === 'totp'
                        ? 'bg-[#F6821F]/15 border-[#F6821F] text-white'
                        : 'bg-[#090D16] border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <KeyRound className="w-3.5 h-3.5" />
                    <span>App Autenticador (TOTP)</span>
                  </button>
                )}
                {mfaPending.availableMethods.includes('sms') && (
                  <button
                    type="button"
                    onClick={() => setMfaMethod('sms')}
                    className={`flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-md border transition-colors ${
                      mfaMethod === 'sms'
                        ? 'bg-[#F6821F]/15 border-[#F6821F] text-white'
                        : 'bg-[#090D16] border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Smartphone className="w-3.5 h-3.5" />
                    <span>SMS OTP {mfaPending.phoneMasked ? `(${mfaPending.phoneMasked})` : ''}</span>
                  </button>
                )}
                {mfaPending.availableMethods.includes('backup_code') && (
                  <button
                    type="button"
                    onClick={() => setMfaMethod('backup_code')}
                    className={`flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-md border transition-colors ${
                      mfaMethod === 'backup_code'
                        ? 'bg-[#F6821F]/15 border-[#F6821F] text-white'
                        : 'bg-[#090D16] border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <span>Código de Backup</span>
                  </button>
                )}
              </div>

              {mfaMethod === 'sms' && (
                <div className="p-4 rounded-md bg-[#090D16] border border-slate-800 space-y-3">
                  <div className="flex items-center justify-between gap-4">
                    <span className="text-xs text-slate-300">
                      Envie um código OTP de 6 dígitos para {mfaPending.phoneMasked || 'seu telefone'}.
                    </span>
                    <button
                      type="button"
                      onClick={handleSendSmsOtp}
                      disabled={loading}
                      className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-white rounded whitespace-nowrap shrink-0"
                    >
                      Enviar Código SMS
                    </button>
                  </div>
                  {smsPreview && (
                    <div className="flex items-center gap-2 text-xs text-emerald-400 font-mono tabular-nums">
                      <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                      <span>Preview Sandbox SMS OTP: {smsPreview}</span>
                    </div>
                  )}
                </div>
              )}

              <form onSubmit={handleVerifyMfa} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1.5">
                    {mfaMethod === 'backup_code' ? 'Código de Backup (XXXX-XXXX)' : 'Código de Verificação (6 dígitos)'}
                  </label>
                  <input
                    type="text"
                    required
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value)}
                    placeholder={mfaMethod === 'backup_code' ? 'A1B2-C3D4' : '000000'}
                    className="w-full bg-[#090D16] border border-slate-700/80 rounded-md px-3.5 py-2.5 text-base font-mono tabular-nums tracking-widest text-white focus:outline-none focus:border-[#F6821F]"
                  />
                </div>
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-[#F6821F] hover:bg-[#e27316] disabled:opacity-50 text-slate-950 font-semibold text-sm py-2.5 px-4 rounded-md transition-colors"
                >
                  {loading ? 'Validando 2FA...' : 'Confirmar 2FA e Emitir JWT'}
                </button>
              </form>
            </div>
          )}
        </div>

        {/* Contas de Demonstração Panel (Hidden when executionEnvironment === 'Produção') */}
        {showDemoPanel && (
          <div className="lg:col-span-5 bg-[#111827] border border-slate-800/90 rounded-lg p-7 space-y-5">
            <div className="space-y-1.5 pb-4 border-b border-slate-800/80">
              <p className="text-xs font-medium text-[#F6821F]">Ambiente: {executionEnvironment}</p>
              <h2 className="font-display text-base font-semibold text-white">Contas de Demonstração</h2>
              <p className="text-xs text-slate-400 leading-relaxed">
                Selecione uma conta abaixo para preencher rapidamente as credenciais de acesso no ambiente de{' '}
                {executionEnvironment?.toLowerCase()}.
              </p>
            </div>

            <div className="grid grid-cols-1 gap-2.5">
              <button
                type="button"
                onClick={() => {
                  setMfaPending(null);
                  setError(null);
                  setEmail('admin@vektor.iam');
                  setPassword('Vektor@2026!');
                }}
                className="text-left px-3.5 py-3 rounded-md bg-[#090D16] border border-slate-800 hover:border-slate-600 transition-colors"
              >
                <div className="text-xs font-medium text-slate-200">Administrador Global</div>
                <div className="text-[11px] font-mono text-slate-400 truncate mt-0.5">
                  admin@vektor.iam · Vektor@2026!
                </div>
              </button>
              <button
                type="button"
                onClick={() => {
                  setMfaPending(null);
                  setError(null);
                  setEmail('clara.silva@vektor.iam');
                  setPassword('Clara@2026!');
                }}
                className="text-left px-3.5 py-3 rounded-md bg-[#090D16] border border-slate-800 hover:border-slate-600 transition-colors"
              >
                <div className="text-xs font-medium text-slate-200">Operadora (2FA SMS Ativo)</div>
                <div className="text-[11px] font-mono text-slate-400 truncate mt-0.5">
                  clara.silva@vektor.iam · Clara@2026!
                </div>
              </button>
            </div>

            {currentSystem && (
              <div className="pt-4 border-t border-slate-800/80 space-y-2 text-xs text-slate-400">
                <div className="flex items-center justify-between">
                  <span>Sistema Alvo</span>
                  <span className="font-mono text-slate-200">{currentSystem.slug}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Assinatura JWT</span>
                  <span className="font-mono tabular-nums text-slate-200">{currentSystem.signingAlg}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Expiração do Token</span>
                  <span className="font-mono tabular-nums text-slate-200">{currentSystem.jwtTtlSeconds}s</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Cache de Borda</span>
                  <span className="font-mono tabular-nums text-slate-200">{currentSystem.edgeCacheTtl}s</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Política 2FA</span>
                  <span className={currentSystem.requireMfa ? 'text-amber-400 font-medium' : 'text-slate-300'}>
                    {currentSystem.requireMfa ? 'Obrigatório' : 'Opcional / Perfil'}
                  </span>
                </div>
              </div>
            )}
          </div>
        )}
      </main>

      {/* External IdP Simulation Modal */}
      {idpModal && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="max-w-md w-full bg-[#111827] border border-slate-700 rounded-lg p-6 space-y-5">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="font-display text-base font-semibold text-white">
                  Federação Externa · {idpModal.name}
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Simule o retorno OIDC/SAML deste provedor para testar provisionamento JIT e desafio 2FA.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setIdpModal(null)}
                className="text-xs text-slate-400 hover:text-white"
              >
                Fechar
              </button>
            </div>
            <form onSubmit={handleConfirmIdpSimulation} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">E-mail retornado pelo IdP</label>
                <input
                  type="email"
                  required
                  value={idpEmail}
                  onChange={(e) => setIdpEmail(e.target.value)}
                  placeholder="usuario@empresa.com"
                  className="w-full bg-[#090D16] border border-slate-700 rounded-md px-3 py-2 text-sm text-white"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Nome exibido</label>
                <input
                  type="text"
                  required
                  value={idpName}
                  onChange={(e) => setIdpName(e.target.value)}
                  className="w-full bg-[#090D16] border border-slate-700 rounded-md px-3 py-2 text-sm text-white"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIdpModal(null)}
                  className="px-4 py-2 text-xs text-slate-300 hover:text-white rounded-md border border-slate-700"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-4 py-2 text-xs font-semibold bg-[#F6821F] text-slate-950 rounded-md"
                >
                  Concluir Login Federado
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <footer className="max-w-6xl w-full mx-auto pt-4 border-t border-slate-800/60 flex items-center justify-between text-xs text-slate-500">
        <span>{platformName}</span>
        <span>Arquitetura Edge SQLite & Cloudflare D1</span>
      </footer>
    </div>
  );
};

