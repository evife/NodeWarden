import { Cipher, Env } from '../types';
import { StorageService } from './storage';
import { generateUUID } from '../utils/uuid';

type PushTokenCache = {
  token: string;
  expiresAt: number;
};

export enum PushUpdateType {
  SyncCipherUpdate = 0,
  SyncCipherCreate = 1,
  SyncLoginDelete = 2,
  SyncFolderDelete = 3,
  SyncCiphers = 4,
  SyncVault = 5,
  SyncOrgKeys = 6,
  SyncFolderCreate = 7,
  SyncFolderUpdate = 8,
  SyncSettings = 10,
  LogOut = 11,
  SyncSendCreate = 12,
  SyncSendUpdate = 13,
  SyncSendDelete = 14,
  AuthRequest = 15,
  AuthRequestResponse = 16,
  None = 100,
}

let cachedPushToken: PushTokenCache | null = null;
let pushTokenPromise: Promise<string | null> | null = null;

function toTruth(value: string | boolean | undefined): boolean {
  if (value === undefined) return true;
  if (typeof value === 'boolean') return value;
  const normalized = String(value).trim().toLowerCase();
  return ['1', 'true', 'yes', 'on'].includes(normalized);
}

function getPushIdentityUri(env: Env): string {
  const raw = (env.PUSH_IDENTITY_URI || '').trim();
  return raw || 'https://identity.bitwarden.com';
}

function getPushRelayUri(env: Env): string {
  const raw = (env.PUSH_RELAY_URI || '').trim();
  return raw || 'https://push.bitwarden.com';
}

function getInstallationId(env: Env): string {
  return (env.PUSH_INSTALLATION_ID || '').trim();
}

function getInstallationKey(env: Env): string {
  return (env.PUSH_INSTALLATION_KEY || '').trim();
}

export function isPushEnabled(env: Env): boolean {
  if (!toTruth(env.PUSH_ENABLED)) return false;
  return !!getInstallationId(env) && !!getInstallationKey(env);
}

async function getPushAuthToken(env: Env): Promise<string | null> {
  if (!isPushEnabled(env)) return null;
  const now = Date.now();
  if (cachedPushToken && cachedPushToken.expiresAt > now + 30_000) {
    return cachedPushToken.token;
  }
  if (pushTokenPromise) return pushTokenPromise;

  pushTokenPromise = (async () => {
    const installationId = getInstallationId(env);
    const installationKey = getInstallationKey(env);
    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'api.push',
      client_id: `installation.${installationId}`,
      client_secret: installationKey,
    });
    const response = await fetch(`${getPushIdentityUri(env)}/connect/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body,
    });
    if (!response.ok) {
      return null;
    }
    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      return null;
    }
    const record = payload as { access_token?: string; expires_in?: number };
    const token = typeof record.access_token === 'string' ? record.access_token : '';
    const expiresIn = typeof record.expires_in === 'number' ? record.expires_in : 0;
    if (!token) return null;
    cachedPushToken = {
      token,
      expiresAt: now + Math.max(30, Math.floor(expiresIn / 2)) * 1000,
    };
    return token;
  })();

  const token = await pushTokenPromise;
  pushTokenPromise = null;
  return token;
}

async function sendToPushRelay(env: Env, payload: Record<string, unknown>): Promise<boolean> {
  const token = await getPushAuthToken(env);
  if (!token) return false;
  const response = await fetch(`${getPushRelayUri(env)}/push/send`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
  });
  return response.ok;
}

async function registerWithPushRelay(
  env: Env,
  payload: Record<string, unknown>
): Promise<boolean> {
  const token = await getPushAuthToken(env);
  if (!token) return false;
  const response = await fetch(`${getPushRelayUri(env)}/push/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
  });
  return response.ok;
}

export async function registerPushDevice(
  env: Env,
  storage: StorageService,
  userId: string,
  deviceIdentifier: string,
  pushToken: string
): Promise<boolean> {
  const device = await storage.getDeviceByUserIdAndIdentifier(userId, deviceIdentifier);
  if (!device) return false;
  const pushUuid = device.pushUuid || generateUUID();
  await storage.updateDevicePushToken(userId, deviceIdentifier, pushToken, pushUuid);
  if (!isPushEnabled(env)) return true;
  const payload = {
    deviceId: pushUuid,
    pushToken: pushToken,
    userId: userId,
    type: device.type,
    identifier: device.deviceIdentifier,
    installationId: getInstallationId(env),
  };
  return registerWithPushRelay(env, payload);
}

export async function sendCipherPush(
  env: Env,
  storage: StorageService,
  cipher: Cipher,
  updateType: PushUpdateType,
  actingDeviceIdentifier: string | null
): Promise<void> {
  if (!isPushEnabled(env)) return;
  const hasDevice = await storage.userHasPushDevice(cipher.userId);
  if (!hasDevice) return;
  const actingDevice = actingDeviceIdentifier
    ? await storage.getDeviceByUserIdAndIdentifier(cipher.userId, actingDeviceIdentifier)
    : null;
  const payload = {
    userId: cipher.userId,
    organizationId: null,
    deviceId: actingDevice?.pushUuid ?? null,
    identifier: actingDevice?.deviceIdentifier ?? null,
    type: updateType,
    payload: {
      id: cipher.id,
      userId: cipher.userId,
      organizationId: null,
      collectionIds: null,
      revisionDate: cipher.updatedAt,
    },
    clientType: null,
    installationId: null,
  };
  await sendToPushRelay(env, payload);
}

export async function sendLoginPush(
  env: Env,
  storage: StorageService,
  userId: string,
  actingDeviceIdentifier: string | null
): Promise<void> {
  if (!isPushEnabled(env)) return;
  const hasDevice = await storage.userHasPushDevice(userId);
  if (!hasDevice) return;
  const actingDevice = actingDeviceIdentifier
    ? await storage.getDeviceByUserIdAndIdentifier(userId, actingDeviceIdentifier)
    : null;
  const payload = {
    userId: userId,
    organizationId: null,
    deviceId: actingDevice?.pushUuid ?? null,
    identifier: actingDevice?.deviceIdentifier ?? null,
    type: PushUpdateType.SyncVault,
    payload: {
      userId: userId,
      date: new Date().toISOString(),
    },
    clientType: null,
    installationId: null,
  };
  await sendToPushRelay(env, payload);
}
