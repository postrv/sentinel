/**
 * Rate Limiting Middleware
 *
 * Implements sliding window rate limiting using KV storage.
 */

import type { Env, AuthContext, RateLimitResult } from '../types';
import { corsHeaders, getCorsHeaders } from './auth';

/**
 * Get the current minute window key
 */
function getMinuteWindow(): string {
  const now = new Date();
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}-${String(now.getUTCDate()).padStart(2, '0')}T${String(now.getUTCHours()).padStart(2, '0')}:${String(now.getUTCMinutes()).padStart(2, '0')}`;
}

/**
 * Get the current day window key
 */
function getDayWindow(): string {
  const now = new Date();
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}-${String(now.getUTCDate()).padStart(2, '0')}`;
}

/**
 * Get identifier for rate limiting (API key hash or IP address)
 */
function getRateLimitKey(request: Request, auth: AuthContext): string {
  if (auth.apiKeyId) {
    return `key:${auth.apiKeyId}`;
  }

  // Fall back to IP address for unauthenticated requests
  const ip = request.headers.get('CF-Connecting-IP') ||
             request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
             'unknown';

  return `ip:${ip}`;
}

/**
 * Check and update rate limit using KV
 */
export async function checkRateLimit(
  request: Request,
  env: Env,
  auth: AuthContext
): Promise<RateLimitResult> {
  const identifier = getRateLimitKey(request, auth);
  const minuteWindow = getMinuteWindow();
  const dayWindow = getDayWindow();

  // Stricter limits for unauthenticated requests to prevent abuse
  const isAuthenticated = auth.isAuthenticated;
  const minuteLimit = isAuthenticated ? (auth.rateLimitPerMinute || 30) : 10;
  const dayLimit = isAuthenticated ? (auth.rateLimitPerDay || 1000) : 100;

  // Check minute limit
  const minuteKey = `ratelimit:minute:${identifier}:${minuteWindow}`;
  const minuteCountStr = await env.CACHE.get(minuteKey);
  const minuteCount = minuteCountStr ? parseInt(minuteCountStr, 10) : 0;

  if (minuteCount >= minuteLimit) {
    const now = new Date();
    const nextMinute = new Date(now);
    nextMinute.setUTCSeconds(0, 0);
    nextMinute.setUTCMinutes(nextMinute.getUTCMinutes() + 1);
    const retryAfter = Math.ceil((nextMinute.getTime() - now.getTime()) / 1000);

    return {
      allowed: false,
      remaining: 0,
      resetAt: nextMinute.getTime(),
      retryAfter,
    };
  }

  // Check day limit
  const dayKey = `ratelimit:day:${identifier}:${dayWindow}`;
  const dayCountStr = await env.CACHE.get(dayKey);
  const dayCount = dayCountStr ? parseInt(dayCountStr, 10) : 0;

  if (dayCount >= dayLimit) {
    const now = new Date();
    const tomorrow = new Date(now);
    tomorrow.setUTCHours(0, 0, 0, 0);
    tomorrow.setUTCDate(tomorrow.getUTCDate() + 1);
    const retryAfter = Math.ceil((tomorrow.getTime() - now.getTime()) / 1000);

    return {
      allowed: false,
      remaining: 0,
      resetAt: tomorrow.getTime(),
      retryAfter,
    };
  }

  // Increment counters
  await Promise.all([
    env.CACHE.put(minuteKey, String(minuteCount + 1), { expirationTtl: 120 }), // 2 min TTL
    env.CACHE.put(dayKey, String(dayCount + 1), { expirationTtl: 86400 + 3600 }), // 25 hour TTL
  ]);

  const now = new Date();
  const nextMinute = new Date(now);
  nextMinute.setUTCSeconds(0, 0);
  nextMinute.setUTCMinutes(nextMinute.getUTCMinutes() + 1);

  return {
    allowed: true,
    remaining: Math.min(minuteLimit - minuteCount - 1, dayLimit - dayCount - 1),
    resetAt: nextMinute.getTime(),
  };
}

/**
 * Create rate limit exceeded response
 */
export function rateLimitExceededResponse(result: RateLimitResult, request?: Request): Response {
  const cors = request ? getCorsHeaders(request) : corsHeaders;
  return new Response(
    JSON.stringify({
      error: 'Rate limit exceeded',
      remaining: result.remaining,
      resetAt: new Date(result.resetAt).toISOString(),
      retryAfter: result.retryAfter,
    }),
    {
      status: 429,
      headers: {
        ...cors,
        'Content-Type': 'application/json',
        'Retry-After': String(result.retryAfter || 60),
        'X-RateLimit-Remaining': String(result.remaining),
        'X-RateLimit-Reset': new Date(result.resetAt).toISOString(),
      },
    }
  );
}

/**
 * Add rate limit headers to response
 */
export function addRateLimitHeaders(response: Response, result: RateLimitResult): Response {
  const headers = new Headers(response.headers);
  headers.set('X-RateLimit-Remaining', String(result.remaining));
  headers.set('X-RateLimit-Reset', new Date(result.resetAt).toISOString());

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/**
 * Rate limiting middleware wrapper
 */
export function withRateLimit(
  handler: (request: Request, env: Env, ctx: ExecutionContext, auth: AuthContext) => Promise<Response>
): (request: Request, env: Env, ctx: ExecutionContext, auth: AuthContext) => Promise<Response> {
  return async (request: Request, env: Env, ctx: ExecutionContext, auth: AuthContext): Promise<Response> => {
    const rateLimitResult = await checkRateLimit(request, env, auth);

    if (!rateLimitResult.allowed) {
      return rateLimitExceededResponse(rateLimitResult);
    }

    const response = await handler(request, env, ctx, auth);
    return addRateLimitHeaders(response, rateLimitResult);
  };
}
