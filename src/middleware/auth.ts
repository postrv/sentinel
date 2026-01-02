/**
 * Authentication Middleware
 *
 * Handles API key validation and authorization.
 */

import type { Env, AuthContext } from '../types';

// CORS headers for all responses
export const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
};

/**
 * Hash a string using SHA-256
 */
async function hashApiKey(key: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(key);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Extract API key from request headers
 */
function extractApiKey(request: Request): string | null {
  // Check X-API-Key header first
  const apiKeyHeader = request.headers.get('X-API-Key');
  if (apiKeyHeader) {
    return apiKeyHeader;
  }

  // Check Authorization header (Bearer token)
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }

  return null;
}

/**
 * Validate API key against database
 */
export async function validateApiKey(
  request: Request,
  env: Env
): Promise<AuthContext> {
  // If no API_SECRET_KEY is configured, allow all requests (development mode)
  if (!env.API_SECRET_KEY && !env.DB) {
    return {
      isAuthenticated: true,
      permissions: ['read', 'analyze'],
      rateLimitPerMinute: 60,
      rateLimitPerDay: 10000,
    };
  }

  const apiKey = extractApiKey(request);

  // No API key provided
  if (!apiKey) {
    return { isAuthenticated: false };
  }

  // Check against simple secret key (for quick setup)
  if (env.API_SECRET_KEY && apiKey === env.API_SECRET_KEY) {
    return {
      isAuthenticated: true,
      permissions: ['read', 'analyze', 'admin'],
      rateLimitPerMinute: 120,
      rateLimitPerDay: 50000,
    };
  }

  // Check against database (for production multi-key setup)
  try {
    const keyHash = await hashApiKey(apiKey);

    const result = await env.DB.prepare(
      `SELECT id, permissions, rate_limit_per_minute, rate_limit_per_day, is_active, expires_at
       FROM api_keys
       WHERE key_hash = ? AND is_active = 1`
    ).bind(keyHash).first<{
      id: number;
      permissions: string;
      rate_limit_per_minute: number;
      rate_limit_per_day: number;
      is_active: number;
      expires_at: string | null;
    }>();

    if (!result) {
      return { isAuthenticated: false };
    }

    // Check expiration
    if (result.expires_at && new Date(result.expires_at) < new Date()) {
      return { isAuthenticated: false };
    }

    // Update last_used_at
    await env.DB.prepare(
      `UPDATE api_keys SET last_used_at = ? WHERE id = ?`
    ).bind(new Date().toISOString(), result.id).run();

    return {
      isAuthenticated: true,
      apiKeyId: result.id,
      permissions: JSON.parse(result.permissions),
      rateLimitPerMinute: result.rate_limit_per_minute,
      rateLimitPerDay: result.rate_limit_per_day,
    };
  } catch (error) {
    console.error('Auth error:', error);
    return { isAuthenticated: false };
  }
}

/**
 * Create authentication error response
 */
export function unauthorizedResponse(message: string = 'Unauthorized'): Response {
  return new Response(
    JSON.stringify({ error: message }),
    {
      status: 401,
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
        'WWW-Authenticate': 'Bearer realm="Sentinel API"',
      },
    }
  );
}

/**
 * Create forbidden response for insufficient permissions
 */
export function forbiddenResponse(message: string = 'Forbidden'): Response {
  return new Response(
    JSON.stringify({ error: message }),
    {
      status: 403,
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
      },
    }
  );
}

/**
 * Check if auth context has required permission
 */
export function hasPermission(auth: AuthContext, permission: string): boolean {
  if (!auth.isAuthenticated) {
    return false;
  }
  return auth.permissions?.includes(permission) || auth.permissions?.includes('admin') || false;
}

/**
 * Authentication middleware wrapper
 */
export function withAuth(
  handler: (request: Request, env: Env, ctx: ExecutionContext, auth: AuthContext) => Promise<Response>,
  requiredPermission?: string
): (request: Request, env: Env, ctx: ExecutionContext) => Promise<Response> {
  return async (request: Request, env: Env, ctx: ExecutionContext): Promise<Response> => {
    const auth = await validateApiKey(request, env);

    if (!auth.isAuthenticated) {
      return unauthorizedResponse('Invalid or missing API key');
    }

    if (requiredPermission && !hasPermission(auth, requiredPermission)) {
      return forbiddenResponse(`Missing required permission: ${requiredPermission}`);
    }

    return handler(request, env, ctx, auth);
  };
}

/**
 * Log API access for audit trail
 */
export async function logAccess(
  env: Env,
  auth: AuthContext,
  request: Request,
  response: Response,
  durationMs: number
): Promise<void> {
  try {
    const url = new URL(request.url);

    await env.DB.prepare(
      `INSERT INTO audit_log (api_key_id, action, indicator, ip_address, user_agent, request_path, response_status, duration_ms, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      auth.apiKeyId || null,
      request.method,
      url.searchParams.get('indicator') || null,
      request.headers.get('CF-Connecting-IP') || 'unknown',
      request.headers.get('User-Agent') || 'unknown',
      url.pathname,
      response.status,
      durationMs,
      new Date().toISOString()
    ).run();
  } catch (error) {
    // Don't fail the request if logging fails
    console.error('Audit log error:', error);
  }
}
