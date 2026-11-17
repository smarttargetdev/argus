import React, { useEffect, useState } from 'react';
import {
  ShieldCheck,
  Smartphone,
  KeyRound,
  Download,
  Lock,
  LogOut,
  FileCheck2,
  AlertTriangle,
} from 'lucide-react';
import { gqlRequest } from '../lib/graphqlClient';
import type { ComplianceSummary, IamSystem, IamUser } from '../types/iam';

interface ProfileAndComplianceProps {
  token: string;
  mode: 'profile' | 'compliance';
  onNotify: (msg: string) => void;
  onSessionInvalidated: () => void;
}

const PROFILE_QUERY = `
  query CentralizedProfileAndLgpd {
    me {
      id
      email
      displayName
      phoneNumber
      phoneVerified
      mfaPreferredMethod
      totpEnabled
      status
      permVersion
      lastLoginAt
      bindings {
        id
        systemId
        systemName
        systemSlug
        roleName
        permissions
      }
      sessions {
        id
        systemName
        jti
        authMethod
        ipMasked
        userAgent
        expiresAt
        revokedAt
        createdAt
      }
      consents {
        id
        systemId
        systemName
        policyVersion
        purposes
        granted
        updatedAt
      }
      externalIdentities {
        id
        providerType
        externalEmail
        linkedAt
      }
    }
    systems {
      id
      name
      slug
      privacyPolicyVersion
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
  }
`;

export const ProfileAndCompliance: React.FC<ProfileAndComplianceProps> = ({
  token,
  mode,
  onNotify,
  onSessionInvalidated,
}) => {
  const [me, setMe] = useState<IamUser | null>(null);
  const [systems, setSystems] = useState<IamSystem[]>([]);
  const [compliance, setCompliance] = useState<ComplianceSummary | null>(null);

  // Profile Form
  const [displayName, setDisplayName] = useState('');
  const [phoneNumber, setPhoneNumber] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');

  // TOTP Setup
  const [totpSetup, setTotpSetup] = useState<{
    secretBase32: string;
    otpauthUri: string;
    qrSvg: string;
  } | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);

  // SMS Setup
  const [smsPhoneInput, setSmsPhoneInput] = useState('');
  const [smsSentPreview, setSmsSentPreview] = useState<string | null>(null);
  const [smsCodeInput, setSmsCodeInput] = useState('');

  // Anonymize Confirmation
  const [confirmAnonModal, setConfirmAnonModal] = useState(false);

  const loadProfile = async () => {
    try {
      const { data } = await gqlRequest<{
        me: IamUser;
        systems: IamSystem[];
        complianceSummary: ComplianceSummary;
      }>({
        token,
        query: PROFILE_QUERY,
        operationName: 'CentralizedProfileAndLgpd',
        bypassCache: true,
      });
      setMe(data.me);
      setSystems(data.systems);
      setCompliance(data.complianceSummary);
      if (data.me) {
        setDisplayName(data.me.displayName);
        setPhoneNumber(data.me.phoneNumber || '');
        setSmsPhoneInput(data.me.phoneNumber || '+55 11 99999-0000');
      }
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro ao carregar perfil.');
    }
  };

  useEffect(() => {
    void loadProfile();
  }, [token]);

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await gqlRequest({
        token,
        operationName: 'UpdateProfile',
        query: `
          mutation UpdateProfile($displayName: String!, $phoneNumber: String) {
            updateProfile(displayName: $displayName, phoneNumber: $phoneNumber) { id displayName }
          }
        `,
        variables: { displayName, phoneNumber: phoneNumber || null },
      });
      onNotify('Dados do perfil atualizados via GraphQL.');
      await loadProfile();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro ao atualizar perfil.');
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const { data } = await gqlRequest<{ changePassword: { message: string } }>({
        token,
        operationName: 'ChangePassword',
        query: `
          mutation ChangePassword($currentPassword: String!, $newPassword: String!) {
            changePassword(currentPassword: $currentPassword, newPassword: $newPassword) { success message }
          }
        `,
        variables: { currentPassword, newPassword },
      });
      setCurrentPassword('');
      setNewPassword('');
      onNotify(data.changePassword.message);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro ao alterar senha.');
    }
  };

  const handleStartTotp = async () => {
    try {
      const { data } = await gqlRequest<{
        setupTotp: { secretBase32: string; otpauthUri: string; qrSvg: string };
      }>({
        token,
        operationName: 'SetupTotp',
        query: `mutation SetupTotp { setupTotp { secretBase32 otpauthUri qrSvg } }`,
      });
      setTotpSetup(data.setupTotp);
      setBackupCodes(null);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro ao iniciar TOTP.');
    }
  };

  const handleVerifyEnableTotp = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const { data } = await gqlRequest<{
        verifyAndEnableTotp: { enabled: boolean; backupCodes: string[] };
      }>({
        token,
        operationName: 'VerifyEnableTotp',
        query: `
          mutation VerifyEnableTotp($code: String!) {
            verifyAndEnableTotp(code: $code) { enabled backupCodes }
          }
        `,
        variables: { code: totpCode },
      });
      setTotpSetup(null);
      setTotpCode('');
      setBackupCodes(data.verifyAndEnableTotp.backupCodes);
      onNotify('Autenticador TOTP ativado! Salve seus códigos de backup.');
      await loadProfile();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Código TOTP inválido.');
    }
  };

  const handleDisableTotp = async () => {
    try {
      await gqlRequest({
        token,
        operationName: 'DisableTotp',
        query: `mutation DisableTotp { disableTotp { success message } }`,
      });
      setBackupCodes(null);
      onNotify('TOTP desativado.');
      await loadProfile();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro ao desativar TOTP.');
    }
  };

  const handleRequestSmsOtp = async () => {
    try {
      const { data } = await gqlRequest<{
        requestSmsSetup: { sent: boolean; maskedPhone: string; sandboxCodePreview: string };
      }>({
        token,
        operationName: 'RequestSmsSetup',
        query: `
          mutation RequestSmsSetup($phoneNumber: String!) {
            requestSmsSetup(phoneNumber: $phoneNumber) { sent maskedPhone sandboxCodePreview }
          }
        `,
        variables: { phoneNumber: smsPhoneInput },
      });
      setSmsSentPreview(data.requestSmsSetup.sandboxCodePreview);
      onNotify(`Código SMS enviado para ${data.requestSmsSetup.maskedPhone}.`);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro ao enviar SMS OTP.');
    }
  };

  const handleVerifySms = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await gqlRequest({
        token,
        operationName: 'VerifyEnableSms',
        query: `
          mutation VerifyEnableSms($phoneNumber: String!, $code: String!) {
            verifyAndEnableSms(phoneNumber: $phoneNumber, code: $code) { success message }
          }
        `,
        variables: { phoneNumber: smsPhoneInput, code: smsCodeInput },
      });
      setSmsSentPreview(null);
      setSmsCodeInput('');
      onNotify('Verificação 2FA por SMS ativada com sucesso.');
      await loadProfile();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Código SMS inválido.');
    }
  };

  const handleDisableSms = async () => {
    try {
      await gqlRequest({
        token,
        operationName: 'DisableSms',
        query: `mutation DisableSms { disableSms { success message } }`,
      });
      onNotify('2FA por SMS desativado.');
      await loadProfile();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro ao desativar SMS.');
    }
  };

  const handleSetPreferredMfa = async (method: string) => {
    try {
      await gqlRequest({
        token,
        operationName: 'SetPrefMfa',
        query: `mutation SetPrefMfa($method: String!) { setPreferredMfaMethod(method: $method) { success message } }`,
        variables: { method },
      });
      onNotify(`Método 2FA preferencial definido para ${method.toUpperCase()}.`);
      await loadProfile();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro ao alterar preferência.');
    }
  };

  const handleRevokeSession = async (sessionId: string) => {
    try {
      await gqlRequest({
        token,
        operationName: 'RevokeSession',
        query: `mutation RevokeSession($sessionId: ID!) { revokeSession(sessionId: $sessionId) { success message } }`,
        variables: { sessionId },
      });
      onNotify('Sessão revogada instantaneamente na borda.');
      await loadProfile();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro ao revogar sessão.');
    }
  };

  const handleToggleConsent = async (systemId: string, granted: boolean) => {
    try {
      await gqlRequest({
        token,
        operationName: 'RecordConsent',
        query: `
          mutation RecordConsent($systemId: ID!, $granted: Boolean!, $purposes: [String!]) {
            recordConsent(systemId: $systemId, granted: $granted, purposes: $purposes) { success message }
          }
        `,
        variables: { systemId, granted, purposes: ['authentication', 'security_audit', 'rbac_claims'] },
      });
      onNotify(granted ? 'Consentimento LGPD/GDPR registrado.' : 'Consentimento revogado.');
      await loadProfile();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro ao atualizar consentimento.');
    }
  };

  const handleExportSarJson = async () => {
    try {
      const { data } = await gqlRequest<{ exportMyDataJson: string }>({
        token,
        operationName: 'ExportSar',
        query: `query ExportSar { exportMyDataJson }`,
      });
      const blob = new Blob([data.exportMyDataJson], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `smarties-gate-portabilidade-lgpd-${me?.id || 'titular'}.json`;
      a.click();
      URL.revokeObjectURL(url);
      onNotify('Pacote JSON de portabilidade LGPD/GDPR exportado.');
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro na exportação LGPD.');
    }
  };

  const handleAnonymizeSelf = async () => {
    if (!me) return;
    try {
      await gqlRequest({
        token,
        operationName: 'AnonymizeSelf',
        query: `mutation AnonymizeSelf($userId: ID!) { anonymizeUserAccount(userId: $userId) { success message } }`,
        variables: { userId: me.id },
      });
      setConfirmAnonModal(false);
      onNotify('Conta anonimizada conforme LGPD/GDPR. Encerrando sessão...');
      onSessionInvalidated();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro ao anonimizar conta.');
    }
  };

  if (!me) {
    return <div className="py-10 text-center text-xs text-slate-500">Carregando perfil centralizado...</div>;
  }

  return (
    <div className="space-y-6">
      {mode === 'profile' ? (
        <>
          <div>
            <h1 className="font-display text-xl font-semibold text-white">Perfil Centralizado e Autenticação 2FA</h1>
            <p className="text-xs text-slate-400 mt-1">
              Gerencie suas credenciais, configure TOTP (QR Code + Backup Codes) ou SMS OTP, revise acessos por sistema e revogue sessões ativas.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            {/* Credentials & Password */}
            <div className="lg:col-span-5 space-y-5">
              <form onSubmit={handleUpdateProfile} className="bg-[#111827] border border-slate-800/90 rounded-lg p-5 space-y-4">
                <h2 className="text-sm font-semibold text-white">Identidade Centralizada</h2>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">E-mail</label>
                  <input
                    type="text"
                    disabled
                    value={me.email}
                    className="w-full bg-[#090D16] border border-slate-800 rounded px-3 py-2 text-xs font-mono text-slate-400"
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-300 mb-1">Nome de exibição</label>
                  <input
                    type="text"
                    required
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    className="w-full bg-[#090D16] border border-slate-700 rounded px-3 py-2 text-sm text-white"
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-300 mb-1">Telefone</label>
                  <input
                    type="text"
                    value={phoneNumber}
                    onChange={(e) => setPhoneNumber(e.target.value)}
                    className="w-full bg-[#090D16] border border-slate-700 rounded px-3 py-2 text-sm font-mono text-white"
                  />
                </div>
                <button
                  type="submit"
                  className="w-full py-2 text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-white rounded-md"
                >
                  Salvar Perfil
                </button>
              </form>

              <form onSubmit={handleChangePassword} className="bg-[#111827] border border-slate-800/90 rounded-lg p-5 space-y-3.5">
                <div className="flex items-center gap-2">
                  <Lock className="w-4 h-4 text-[#F6821F]" />
                  <h2 className="text-sm font-semibold text-white">Alterar Senha</h2>
                </div>
                <input
                  type="password"
                  required
                  placeholder="Senha atual"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  className="w-full bg-[#090D16] border border-slate-700 rounded px-3 py-2 text-xs text-white"
                />
                <input
                  type="password"
                  required
                  minLength={8}
                  placeholder="Nova senha (mín. 8 caracteres)"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full bg-[#090D16] border border-slate-700 rounded px-3 py-2 text-xs text-white"
                />
                <button
                  type="submit"
                  className="w-full py-2 text-xs font-semibold bg-[#F6821F] text-slate-950 rounded-md"
                >
                  Atualizar Senha
                </button>
              </form>
            </div>

            {/* 2FA Configuration (TOTP + SMS) */}
            <div className="lg:col-span-7 space-y-5">
              <div className="bg-[#111827] border border-slate-800/90 rounded-lg p-5 space-y-5">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-[#F6821F]" />
                    <h2 className="text-sm font-semibold text-white">Configuração de Dois Fatores (2FA)</h2>
                  </div>
                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-slate-400">Preferencial:</span>
                    <select
                      value={me.mfaPreferredMethod}
                      onChange={(e) => void handleSetPreferredMfa(e.target.value)}
                      className="bg-[#090D16] border border-slate-700 rounded px-2 py-1 text-xs font-mono text-white"
                    >
                      <option value="none">Nenhum</option>
                      {me.totpEnabled && <option value="totp">TOTP</option>}
                      {me.phoneVerified && <option value="sms">SMS</option>}
                    </select>
                  </div>
                </div>

                {/* TOTP Section */}
                <div className="p-4 rounded-md bg-[#090D16] border border-slate-800 space-y-4">
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex items-center gap-2.5">
                      <KeyRound className="w-4 h-4 text-slate-300" />
                      <div>
                        <div className="text-xs font-semibold text-white">App Autenticador (TOTP RFC 6238)</div>
                        <div className="text-[11px] text-slate-400">
                          Status: {me.totpEnabled ? 'Ativo · Google Authenticator / Authy' : 'Não configurado'}
                        </div>
                      </div>
                    </div>
                    {me.totpEnabled ? (
                      <button
                        type="button"
                        onClick={handleDisableTotp}
                        className="px-3 py-1.5 text-xs border border-red-800/70 text-red-300 hover:bg-red-950/40 rounded"
                      >
                        Desativar TOTP
                      </button>
                    ) : (
                      <button
                        type="button"
                        onClick={handleStartTotp}
                        className="px-3 py-1.5 text-xs font-semibold bg-[#F6821F] text-slate-950 rounded"
                      >
                        Configurar QR Code
                      </button>
                    )}
                  </div>

                  {totpSetup && (
                    <div className="pt-3 border-t border-slate-800 grid grid-cols-1 sm:grid-cols-12 gap-4 items-center">
                      <div
                        className="sm:col-span-4 bg-slate-900 border border-slate-700 rounded p-2 flex items-center justify-center"
                        dangerouslySetInnerHTML={{ __html: totpSetup.qrSvg }}
                      />
                      <form onSubmit={handleVerifyEnableTotp} className="sm:col-span-8 space-y-3">
                        <div className="text-[11px] font-mono text-slate-400 break-all">
                          Chave manual Base32: <span className="text-slate-200">{totpSetup.secretBase32}</span>
                        </div>
                        <div className="flex gap-2">
                          <input
                            type="text"
                            required
                            value={totpCode}
                            onChange={(e) => setTotpCode(e.target.value)}
                            placeholder="Código 6 dígitos"
                            className="flex-1 bg-[#111827] border border-slate-700 rounded px-3 py-2 text-xs font-mono tabular-nums text-white"
                          />
                          <button
                            type="submit"
                            className="px-4 py-2 text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white rounded"
                          >
                            Ativar
                          </button>
                        </div>
                      </form>
                    </div>
                  )}

                  {backupCodes && (
                    <div className="pt-3 border-t border-slate-800 space-y-2">
                      <div className="text-xs font-semibold text-amber-400">
                        Códigos de Backup Descartáveis (Guarde em local seguro):
                      </div>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-xs text-slate-200">
                        {backupCodes.map((c) => (
                          <div key={c} className="px-2.5 py-1.5 bg-[#111827] border border-slate-700 rounded text-center">
                            {c}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* SMS OTP Section */}
                <div className="p-4 rounded-md bg-[#090D16] border border-slate-800 space-y-3">
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex items-center gap-2.5">
                      <Smartphone className="w-4 h-4 text-slate-300" />
                      <div>
                        <div className="text-xs font-semibold text-white">Verificação por SMS OTP</div>
                        <div className="text-[11px] text-slate-400">
                          Status: {me.phoneVerified ? `Verificado (${me.phoneNumber})` : 'Não verificado'}
                        </div>
                      </div>
                    </div>
                    {me.phoneVerified && (
                      <button
                        type="button"
                        onClick={handleDisableSms}
                        className="px-3 py-1.5 text-xs border border-red-800/70 text-red-300 hover:bg-red-950/40 rounded"
                      >
                        Remover SMS
                      </button>
                    )}
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <input
                      type="text"
                      value={smsPhoneInput}
                      onChange={(e) => setSmsPhoneInput(e.target.value)}
                      placeholder="+55 11 99999-0000"
                      className="flex-1 min-w-[180px] bg-[#111827] border border-slate-700 rounded px-3 py-1.5 text-xs font-mono text-white"
                    />
                    <button
                      type="button"
                      onClick={handleRequestSmsOtp}
                      className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-white rounded"
                    >
                      Enviar Código SMS
                    </button>
                  </div>

                  {smsSentPreview && (
                    <form onSubmit={handleVerifySms} className="pt-2 space-y-2">
                      <div className="text-[11px] font-mono text-emerald-400">
                        Preview Sandbox SMS OTP: {smsSentPreview}
                      </div>
                      <div className="flex gap-2">
                        <input
                          type="text"
                          required
                          value={smsCodeInput}
                          onChange={(e) => setSmsCodeInput(e.target.value)}
                          placeholder="Digite os 6 dígitos"
                          className="flex-1 bg-[#111827] border border-slate-700 rounded px-3 py-1.5 text-xs font-mono text-white"
                        />
                        <button
                          type="submit"
                          className="px-4 py-1.5 text-xs font-semibold bg-[#F6821F] text-slate-950 rounded"
                        >
                          Confirmar SMS
                        </button>
                      </div>
                    </form>
                  )}
                </div>
              </div>

              {/* Active Sessions */}
              <div className="bg-[#111827] border border-slate-800/90 rounded-lg p-5 space-y-3">
                <h2 className="text-sm font-semibold text-white">Sessões JWT Ativas e Histórico Recente</h2>
                <div className="space-y-2 max-h-60 overflow-y-auto">
                  {(me.sessions || []).map((ses) => (
                    <div
                      key={ses.id}
                      className="flex items-center justify-between gap-3 px-3 py-2.5 bg-[#090D16] border border-slate-800 rounded text-xs"
                    >
                      <div className="min-w-0">
                        <div className="font-medium text-white truncate">
                          {ses.systemName} · <span className="font-mono text-slate-400">{ses.authMethod}</span>
                        </div>
                        <div className="text-[11px] font-mono text-slate-500 truncate">
                          IP {ses.ipMasked} · JTI {ses.jti.slice(0, 14)} · {ses.revokedAt ? 'Revogada' : `Expira ${new Date(ses.expiresAt).toLocaleTimeString('pt-BR')}`}
                        </div>
                      </div>
                      {!ses.revokedAt && (
                        <button
                          type="button"
                          onClick={() => handleRevokeSession(ses.id)}
                          className="flex items-center gap-1 px-2.5 py-1 text-[11px] border border-slate-700 hover:border-red-500 text-slate-300 hover:text-red-300 rounded shrink-0"
                        >
                          <LogOut className="w-3 h-3" />
                          <span>Revogar</span>
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </>
      ) : (
        /* LGPD & GDPR Compliance Center */
        <>
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h1 className="font-display text-xl font-semibold text-white">Conformidade LGPD e GDPR</h1>
              <p className="text-xs text-slate-400 mt-1">
                Governança de consentimentos versionados, portabilidade de dados pessoais (SAR), mascaramento de PII e direito ao esquecimento.
              </p>
            </div>
            <button
              type="button"
              onClick={handleExportSarJson}
              className="flex items-center gap-2 px-3.5 py-2 text-xs font-semibold bg-[#F6821F] hover:bg-[#e27316] text-slate-950 rounded-md whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Exportar Meus Dados (JSON)</span>
            </button>
          </div>

          {compliance && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-[#111827] border border-slate-800/90 rounded-lg p-4">
                <div className="text-xs text-slate-400">Consentimentos Ativos</div>
                <div className="font-mono tabular-nums text-2xl font-semibold text-white mt-1">
                  {compliance.activeConsents}
                </div>
                <div className="text-[11px] font-mono text-slate-500 mt-1">
                  {compliance.revokedConsents} revogados
                </div>
              </div>
              <div className="bg-[#111827] border border-slate-800/90 rounded-lg p-4">
                <div className="text-xs text-slate-400">Adoção de 2FA</div>
                <div className="font-mono tabular-nums text-2xl font-semibold text-white mt-1">
                  {compliance.mfaAdoptedUsers} / {compliance.totalUsers}
                </div>
                <div className="text-[11px] font-mono text-slate-500 mt-1">
                  {compliance.totpUsers} TOTP · {compliance.smsUsers} SMS
                </div>
              </div>
              <div className="bg-[#111827] border border-slate-800/90 rounded-lg p-4">
                <div className="text-xs text-slate-400">Logs com PII Mascarado</div>
                <div className="font-mono tabular-nums text-2xl font-semibold text-white mt-1">
                  {compliance.piiMaskedLogsCount}
                </div>
                <div className="text-[11px] font-mono text-slate-500 mt-1">E-mail, IP e subject_hash</div>
              </div>
              <div className="bg-[#111827] border border-slate-800/90 rounded-lg p-4">
                <div className="text-xs text-slate-400">Contas Anonimizadas</div>
                <div className="font-mono tabular-nums text-2xl font-semibold text-white mt-1">
                  {compliance.anonymizedUsers}
                </div>
                <div className="text-[11px] font-mono text-slate-500 mt-1">Art. 18 LGPD / Art. 17 GDPR</div>
              </div>
            </div>
          )}

          {/* Consent Management per System */}
          <div className="bg-[#111827] border border-slate-800/90 rounded-lg p-5 space-y-4">
            <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
              <FileCheck2 className="w-4 h-4 text-[#F6821F]" />
              <h2 className="text-sm font-semibold text-white">Matriz de Consentimento por Sistema (Titular Atual)</h2>
            </div>
            <div className="space-y-2.5">
              {systems.map((sys) => {
                const rec = (me.consents || []).find((c) => c.systemId === sys.id);
                const isGranted = rec ? rec.granted : false;
                return (
                  <div
                    key={sys.id}
                    className="flex flex-wrap items-center justify-between gap-4 px-4 py-3 bg-[#090D16] border border-slate-800 rounded-md"
                  >
                    <div>
                      <div className="text-xs font-semibold text-white">{sys.name}</div>
                      <div className="text-[11px] font-mono text-slate-400">
                        Política v{sys.privacyPolicyVersion} · Finalidades: autenticação, auditoria de segurança, claims RBAC
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={`text-xs font-mono ${isGranted ? 'text-emerald-400' : 'text-slate-400'}`}>
                        {isGranted ? 'Consentido' : 'Não consentido'}
                      </span>
                      <button
                        type="button"
                        onClick={() => void handleToggleConsent(sys.id, !isGranted)}
                        className="px-3 py-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-white rounded"
                      >
                        {isGranted ? 'Revogar' : 'Conceder'}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right to Erasure / Anonymization */}
          <div className="bg-[#111827] border border-red-900/50 rounded-lg p-5 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
              <div>
                <h3 className="text-sm font-semibold text-white">Direito ao Esquecimento e Anonimização (LGPD / GDPR)</h3>
                <p className="text-xs text-slate-400 mt-1 max-w-2xl">
                  Remove irreversivelmente nome, e-mail, telefone, segredos 2FA e vínculos externos, revogando todas as sessões e preservando apenas os hashes pseudonimizados de auditoria legal.
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setConfirmAnonModal(true)}
              className="px-4 py-2 text-xs font-semibold bg-red-600 hover:bg-red-500 text-white rounded-md whitespace-nowrap"
            >
              Solicitar Anonimização
            </button>
          </div>

          {confirmAnonModal && (
            <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
              <div className="max-w-md w-full bg-[#111827] border border-red-800/80 rounded-lg p-6 space-y-4">
                <h3 className="font-display text-base font-semibold text-white">Confirmar Anonimização Irreversível</h3>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Seus dados pessoais serão substituídos de forma permanente e sua sessão atual será encerrada imediatamente. Deseja prosseguir?
                </p>
                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setConfirmAnonModal(false)}
                    className="px-4 py-2 text-xs border border-slate-700 text-slate-300 rounded-md"
                  >
                    Cancelar
                  </button>
                  <button
                    type="button"
                    onClick={handleAnonymizeSelf}
                    className="px-4 py-2 text-xs font-semibold bg-red-600 hover:bg-red-500 text-white rounded-md"
                  >
                    Confirmar Anonimização
                  </button>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};
