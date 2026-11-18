import { db, dbStats, setAuditBatchSize } from './db.ts';

export type ExecutionEnvironment = 'Desenvolvimento' | 'Homologação' | 'Produção';

export interface PlatformSettings {
  executionEnvironment: ExecutionEnvironment;
  platformName: string;
  jwtIssuer: string;
  appBaseUrl: string;
  defaultJwtTtlSeconds: number;
  defaultSigningAlg: 'RS256' | 'HS256';
  sessionWarningSeconds: number;
  oauthCodeTtlSeconds: number;
  pkceRequired: boolean;
  allowSelfRegistration: boolean;
  globalRequireMfa: boolean;
  globalPasswordMinLength: number;
  maxLoginAttempts: number;
  smsOtpTtlSeconds: number;
  smsSandboxPreview: boolean;
  jitProvisioningEnabled: boolean;
  edgeCacheEnabled: boolean;
  defaultEdgeCacheTtl: number;
  auditFlushBatchSize: number;
  auditRetentionDays: number;
  piiMaskingEnabled: boolean;
  telemetryStreamEnabled: boolean;
  healthAlertSoundEnabled: boolean;
  defaultPrivacyPolicyVersion: string;
  requireExplicitConsent: boolean;
  allowDataPortabilityExport: boolean;
  allowSelfErasure: boolean;
  updatedAt: string;
  updatedBy: string;
}

const DEFAULT_SETTINGS: PlatformSettings = {
  executionEnvironment: 'Desenvolvimento',
  platformName: 'Smarties Secure Gate',
  jwtIssuer: process.env.IAM_JWT_ISSUER || 'https://smarties-gate.edge.local',
  appBaseUrl: process.env.APP_URL || '',
  defaultJwtTtlSeconds: 3600,
  defaultSigningAlg: 'RS256',
  sessionWarningSeconds: 300,
  oauthCodeTtlSeconds: 300,
  pkceRequired: false,
  allowSelfRegistration: false,
  globalRequireMfa: false,
  globalPasswordMinLength: 8,
  maxLoginAttempts: 5,
  smsOtpTtlSeconds: 300,
  smsSandboxPreview: true,
  jitProvisioningEnabled: true,
  edgeCacheEnabled: true,
  defaultEdgeCacheTtl: 120,
  auditFlushBatchSize: 20,
  auditRetentionDays: 90,
  piiMaskingEnabled: true,
  telemetryStreamEnabled: true,
  healthAlertSoundEnabled: true,
  defaultPrivacyPolicyVersion: '2026.1',
  requireExplicitConsent: true,
  allowDataPortabilityExport: true,
  allowSelfErasure: true,
  updatedAt: new Date().toISOString(),
  updatedBy: 'system',
};

let cachedSettings: PlatformSettings | null = null;

function sanitizeEnvironment(val: unknown): ExecutionEnvironment {
  if (val === 'Desenvolvimento' || val === 'Homologação' || val === 'Produção') {
    return val;
  }
  return 'Desenvolvimento';
}

function clampInt(val: unknown, fallback: number, min: number, max: number): number {
  const num = Number(val);
  if (!Number.isFinite(num)) return fallback;
  return Math.max(min, Math.min(max, Math.round(num)));
}

function normalizeSettings(raw: Partial<PlatformSettings>, updatedBy = 'system'): PlatformSettings {
  const env = sanitizeEnvironment(raw.executionEnvironment ?? DEFAULT_SETTINGS.executionEnvironment);
  return {
    executionEnvironment: env,
    platformName: String(raw.platformName ?? DEFAULT_SETTINGS.platformName).trim() || 'Smarties Secure Gate',
    jwtIssuer: String(raw.jwtIssuer ?? DEFAULT_SETTINGS.jwtIssuer).trim() || DEFAULT_SETTINGS.jwtIssuer,
    appBaseUrl: String(raw.appBaseUrl ?? DEFAULT_SETTINGS.appBaseUrl).trim(),
    defaultJwtTtlSeconds: clampInt(raw.defaultJwtTtlSeconds, DEFAULT_SETTINGS.defaultJwtTtlSeconds, 60, 86400),
    defaultSigningAlg: raw.defaultSigningAlg === 'HS256' ? 'HS256' : 'RS256',
    sessionWarningSeconds: clampInt(raw.sessionWarningSeconds, DEFAULT_SETTINGS.sessionWarningSeconds, 30, 1800),
    oauthCodeTtlSeconds: clampInt(raw.oauthCodeTtlSeconds, DEFAULT_SETTINGS.oauthCodeTtlSeconds, 60, 1800),
    pkceRequired: Boolean(raw.pkceRequired ?? DEFAULT_SETTINGS.pkceRequired),
    allowSelfRegistration: Boolean(raw.allowSelfRegistration ?? DEFAULT_SETTINGS.allowSelfRegistration),
    globalRequireMfa: Boolean(raw.globalRequireMfa ?? DEFAULT_SETTINGS.globalRequireMfa),
    globalPasswordMinLength: clampInt(raw.globalPasswordMinLength, DEFAULT_SETTINGS.globalPasswordMinLength, 6, 64),
    maxLoginAttempts: clampInt(raw.maxLoginAttempts, DEFAULT_SETTINGS.maxLoginAttempts, 3, 50),
    smsOtpTtlSeconds: clampInt(raw.smsOtpTtlSeconds, DEFAULT_SETTINGS.smsOtpTtlSeconds, 60, 900),
    smsSandboxPreview: Boolean(raw.smsSandboxPreview ?? DEFAULT_SETTINGS.smsSandboxPreview),
    jitProvisioningEnabled: Boolean(raw.jitProvisioningEnabled ?? DEFAULT_SETTINGS.jitProvisioningEnabled),
    edgeCacheEnabled: Boolean(raw.edgeCacheEnabled ?? DEFAULT_SETTINGS.edgeCacheEnabled),
    defaultEdgeCacheTtl: clampInt(raw.defaultEdgeCacheTtl, DEFAULT_SETTINGS.defaultEdgeCacheTtl, 0, 3600),
    auditFlushBatchSize: clampInt(raw.auditFlushBatchSize, DEFAULT_SETTINGS.auditFlushBatchSize, 1, 100),
    auditRetentionDays: clampInt(raw.auditRetentionDays, DEFAULT_SETTINGS.auditRetentionDays, 7, 3650),
    piiMaskingEnabled: Boolean(raw.piiMaskingEnabled ?? DEFAULT_SETTINGS.piiMaskingEnabled),
    telemetryStreamEnabled: Boolean(raw.telemetryStreamEnabled ?? DEFAULT_SETTINGS.telemetryStreamEnabled),
    healthAlertSoundEnabled: Boolean(raw.healthAlertSoundEnabled ?? DEFAULT_SETTINGS.healthAlertSoundEnabled),
    defaultPrivacyPolicyVersion:
      String(raw.defaultPrivacyPolicyVersion ?? DEFAULT_SETTINGS.defaultPrivacyPolicyVersion).trim() || '2026.1',
    requireExplicitConsent: Boolean(raw.requireExplicitConsent ?? DEFAULT_SETTINGS.requireExplicitConsent),
    allowDataPortabilityExport: Boolean(raw.allowDataPortabilityExport ?? DEFAULT_SETTINGS.allowDataPortabilityExport),
    allowSelfErasure: Boolean(raw.allowSelfErasure ?? DEFAULT_SETTINGS.allowSelfErasure),
    updatedAt: raw.updatedAt || new Date().toISOString(),
    updatedBy: raw.updatedBy || updatedBy,
  };
}

function ensureInitialSettingsSeeded(): PlatformSettings {
  const row = db
    .prepare("SELECT setting_value, updated_by, updated_at FROM system_settings WHERE setting_key = 'platform_config'")
    .get() as { setting_value: string; updated_by: string; updated_at: string } | undefined;

  if (row) {
    const parsed = JSON.parse(row.setting_value) as Partial<PlatformSettings>;
    const normalized = normalizeSettings({ ...parsed, updatedAt: row.updated_at, updatedBy: row.updated_by });
    setAuditBatchSize(normalized.auditFlushBatchSize);
    cachedSettings = normalized;
    return normalized;
  }

  const now = new Date().toISOString();
  const initial = normalizeSettings({ ...DEFAULT_SETTINGS, updatedAt: now, updatedBy: 'system' });
  db.prepare(
    'INSERT INTO system_settings (setting_key, setting_value, updated_by, updated_at) VALUES (?, ?, ?, ?)'
  ).run('platform_config', JSON.stringify(initial), 'system', now);
  dbStats.totalWrites += 1;
  setAuditBatchSize(initial.auditFlushBatchSize);
  cachedSettings = initial;
  return initial;
}

export function getPlatformSettings(): PlatformSettings {
  if (cachedSettings) return cachedSettings;
  dbStats.totalReads += 1;
  return ensureInitialSettingsSeeded();
}

export function updatePlatformSettings(
  patch: Partial<PlatformSettings>,
  updatedBy: string
): PlatformSettings {
  const current = getPlatformSettings();
  const now = new Date().toISOString();
  const merged = normalizeSettings(
    {
      ...current,
      ...patch,
      updatedAt: now,
      updatedBy,
    },
    updatedBy
  );

  db.prepare(
    'INSERT OR REPLACE INTO system_settings (setting_key, setting_value, updated_by, updated_at) VALUES (?, ?, ?, ?)'
  ).run('platform_config', JSON.stringify(merged), updatedBy, now);
  dbStats.totalWrites += 1;
  setAuditBatchSize(merged.auditFlushBatchSize);
  cachedSettings = merged;
  return merged;
}

export function resetPlatformSettings(updatedBy: string): PlatformSettings {
  const now = new Date().toISOString();
  const defaults = normalizeSettings({ ...DEFAULT_SETTINGS, updatedAt: now, updatedBy }, updatedBy);
  db.prepare(
    'INSERT OR REPLACE INTO system_settings (setting_key, setting_value, updated_by, updated_at) VALUES (?, ?, ?, ?)'
  ).run('platform_config', JSON.stringify(defaults), updatedBy, now);
  dbStats.totalWrites += 1;
  setAuditBatchSize(defaults.auditFlushBatchSize);
  cachedSettings = defaults;
  return defaults;
}

export function getPublicPlatformConfig() {
  const s = getPlatformSettings();
  return {
    executionEnvironment: s.executionEnvironment,
    platformName: s.platformName,
    allowSelfRegistration: s.allowSelfRegistration,
    sessionWarningSeconds: s.sessionWarningSeconds,
    telemetryStreamEnabled: s.telemetryStreamEnabled,
    healthAlertSoundEnabled: s.healthAlertSoundEnabled,
    defaultJwtTtlSeconds: s.defaultJwtTtlSeconds,
    defaultSigningAlg: s.defaultSigningAlg,
    defaultEdgeCacheTtl: s.defaultEdgeCacheTtl,
    defaultPrivacyPolicyVersion: s.defaultPrivacyPolicyVersion,
    pkceRequired: s.pkceRequired,
  };
}
