import { Env } from '../types';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { sendAuthRequestPush, sendAuthRequestResponsePush } from '../services/push';

function parseDeviceType(value: string | number | undefined | null): number {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.max(0, Math.floor(value));
  }
  const parsed = Number.parseInt(String(value || ''), 10);
  if (Number.isFinite(parsed) && parsed >= 0) return parsed;
  return 14;
}

function resolveRequestIp(request: Request): string {
  const header =
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For') ||
    request.headers.get('X-Real-IP') ||
    '';
  return header.split(',')[0]?.trim() || '';
}

function authRequestToResponse(origin: string, request: any): Record<string, unknown> {
  return {
    id: request.id,
    publicKey: request.publicKey,
    requestDeviceType: String(request.requestDeviceType),
    requestIpAddress: request.requestIp,
    key: request.key,
    masterPasswordHash: request.masterPasswordHash,
    creationDate: request.createdAt,
    responseDate: request.responseDate,
    requestApproved: request.approved,
    origin,
    object: 'auth-request',
  };
}

export async function handleCreateAuthRequest(request: Request, env: Env): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const email = String(body?.email || '').trim().toLowerCase();
  const accessCode = String(body?.accessCode || body?.access_code || '').trim();
  const deviceIdentifier = String(body?.deviceIdentifier || body?.device_identifier || '').trim();
  const publicKey = String(body?.publicKey || body?.public_key || '').trim();
  const deviceType = parseDeviceType(body?.deviceType || body?.device_type || request.headers.get('Device-Type'));

  if (!email || !accessCode || !deviceIdentifier || !publicKey) {
    return errorResponse('Invalid auth request payload', 400);
  }

  const storage = new StorageService(env.DB);
  const user = await storage.getUser(email);
  if (!user) {
    return errorResponse('User not found', 404);
  }

  const now = new Date().toISOString();
  const authRequest = {
    id: generateUUID(),
    userId: user.id,
    requestDeviceIdentifier: deviceIdentifier,
    requestDeviceType: deviceType,
    requestIp: resolveRequestIp(request),
    accessCode,
    publicKey,
    key: null,
    masterPasswordHash: null,
    approved: null,
    createdAt: now,
    responseDate: null,
    responseDeviceIdentifier: null,
  };

  await storage.createAuthRequest(authRequest);
  await sendAuthRequestPush(env, storage, user.id, authRequest.id, deviceIdentifier);

  const origin = new URL(request.url).origin;
  return jsonResponse(authRequestToResponse(origin, authRequest));
}

export async function handleGetAuthRequestsPending(
  request: Request,
  env: Env,
  userId: string
): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const origin = new URL(request.url).origin;
  const pending = await storage.listPendingAuthRequestsByUserId(userId);
  return jsonResponse({
    data: pending.map(item => authRequestToResponse(origin, item)),
    continuationToken: null,
    object: 'list',
  });
}

export async function handleGetAuthRequest(
  request: Request,
  env: Env,
  userId: string,
  authRequestId: string
): Promise<Response> {
  void env;
  const storage = new StorageService(env.DB);
  const authRequest = await storage.getAuthRequestByIdForUser(authRequestId, userId);
  if (!authRequest) {
    return errorResponse('Auth request not found', 404);
  }
  const origin = new URL(request.url).origin;
  return jsonResponse(authRequestToResponse(origin, authRequest));
}

export async function handleUpdateAuthRequest(
  request: Request,
  env: Env,
  userId: string,
  authRequestId: string
): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const deviceIdentifier = String(body?.deviceIdentifier || body?.device_identifier || '').trim() || null;
  const key = body?.key ? String(body.key) : null;
  const masterPasswordHash = body?.masterPasswordHash ? String(body.masterPasswordHash) : null;
  const requestApprovedRaw = body?.requestApproved ?? body?.request_approved;
  const requestApproved = requestApprovedRaw === true || requestApprovedRaw === 'true' || requestApprovedRaw === 1;

  const storage = new StorageService(env.DB);
  const authRequest = await storage.getAuthRequestByIdForUser(authRequestId, userId);
  if (!authRequest) {
    return errorResponse('Auth request not found', 404);
  }

  if (authRequest.approved !== null) {
    return errorResponse('Auth request already handled', 400);
  }

  if (!requestApproved) {
    await storage.deleteAuthRequest(authRequestId);
    return jsonResponse({ success: true });
  }

  await storage.updateAuthRequestResponse(
    authRequestId,
    userId,
    true,
    deviceIdentifier,
    key,
    masterPasswordHash
  );

  await sendAuthRequestResponsePush(env, storage, userId, authRequestId, deviceIdentifier);

  const updated = await storage.getAuthRequestByIdForUser(authRequestId, userId);
  const origin = new URL(request.url).origin;
  return jsonResponse(authRequestToResponse(origin, updated!));
}

export async function handleGetAuthRequestResponse(
  request: Request,
  env: Env,
  authRequestId: string
): Promise<Response> {
  void env;
  const url = new URL(request.url);
  const code = String(url.searchParams.get('code') || '').trim();
  if (!code) {
    return errorResponse('Access code required', 400);
  }

  const storage = new StorageService(env.DB);
  const authRequest = await storage.getAuthRequestById(authRequestId);
  if (!authRequest || authRequest.accessCode !== code) {
    return errorResponse('Auth request not found', 404);
  }

  const origin = url.origin;
  return jsonResponse(authRequestToResponse(origin, authRequest));
}
