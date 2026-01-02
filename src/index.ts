/**
 * Sentinel - Cloudflare Worker
 *
 * Main entry point for the security investigation platform.
 * Handles indicator analysis, threat enrichment, and LLM-powered investigation.
 */

import { parseIPv4, parseDomain, parseURL, parseHash } from './lib/indicators';
import {
  corsHeaders,
  validateApiKey,
  unauthorizedResponse,
  logAccess,
} from './middleware/auth';
import { checkRateLimit, rateLimitExceededResponse, addRateLimitHeaders } from './middleware/rate-limit';
import { enrichIP, enrichDomain, enrichURL, enrichHash } from './services/enrichment';
import { performLLMAnalysis, performLocalAnalysis } from './services/llm';
import { generateMitigations } from './services/mitigations';
import type { Env, AnalysisResult, IndicatorType, AnalyzeRequest, AuthContext } from './types';

// =============================================================================
// INDICATOR TYPE DETECTION
// =============================================================================

function detectIndicatorType(indicator: string): IndicatorType {
  // IPv4
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(indicator)) {
    return 'ip';
  }

  // URL
  if (/^https?:\/\//.test(indicator)) {
    return 'url';
  }

  // Hash (MD5, SHA1, SHA256, SHA512)
  if (/^[a-f0-9]{32,128}$/i.test(indicator)) {
    return 'hash';
  }

  // Default to domain
  return 'domain';
}

// =============================================================================
// ANALYSIS HANDLERS
// =============================================================================

async function handleAnalyzeIP(ip: string, env: Env, useLLM: boolean = true): Promise<AnalysisResult> {
  const parsed = parseIPv4(ip);

  if (!parsed) {
    throw new Error('Invalid IPv4 address');
  }

  // Only enrich routable IPs
  const enrichment = parsed.classification.isInternetRoutable
    ? await enrichIP(ip, env)
    : {};

  // Perform LLM or local analysis
  const llmAnalysis = useLLM && env.ANTHROPIC_API_KEY
    ? await performLLMAnalysis(ip, 'ip', parsed, enrichment, env.ANTHROPIC_API_KEY)
    : performLocalAnalysis(ip, 'ip', parsed, enrichment);

  // Generate mitigations
  const mitigations = generateMitigations(ip, 'ip', parsed, enrichment);

  return {
    indicator: ip,
    type: 'ip',
    parsed,
    enrichment,
    llmAnalysis,
    mitigations,
    timestamp: new Date().toISOString(),
  };
}

async function handleAnalyzeDomain(domain: string, env: Env, useLLM: boolean = true): Promise<AnalysisResult> {
  const parsed = parseDomain(domain);
  const enrichment = await enrichDomain(domain, env);

  const llmAnalysis = useLLM && env.ANTHROPIC_API_KEY
    ? await performLLMAnalysis(domain, 'domain', parsed, enrichment, env.ANTHROPIC_API_KEY)
    : performLocalAnalysis(domain, 'domain', parsed, enrichment);

  const mitigations = generateMitigations(domain, 'domain', parsed, enrichment);

  return {
    indicator: domain,
    type: 'domain',
    parsed,
    enrichment,
    llmAnalysis,
    mitigations,
    timestamp: new Date().toISOString(),
  };
}

async function handleAnalyzeURL(url: string, env: Env, useLLM: boolean = true): Promise<AnalysisResult> {
  const parsed = parseURL(url);

  if (!parsed) {
    throw new Error('Invalid URL');
  }

  const enrichment = await enrichURL(url, parsed.domain.normalized, env);

  const llmAnalysis = useLLM && env.ANTHROPIC_API_KEY
    ? await performLLMAnalysis(url, 'url', parsed, enrichment, env.ANTHROPIC_API_KEY)
    : performLocalAnalysis(url, 'url', parsed, enrichment);

  const mitigations = generateMitigations(url, 'url', parsed, enrichment);

  return {
    indicator: url,
    type: 'url',
    parsed,
    enrichment,
    llmAnalysis,
    mitigations,
    timestamp: new Date().toISOString(),
  };
}

async function handleAnalyzeHash(hash: string, env: Env, useLLM: boolean = true): Promise<AnalysisResult> {
  const parsed = parseHash(hash);

  if (!parsed.isValid) {
    throw new Error('Invalid hash format');
  }

  const enrichment = await enrichHash(hash, env);

  const llmAnalysis = useLLM && env.ANTHROPIC_API_KEY
    ? await performLLMAnalysis(hash, 'hash', parsed, enrichment, env.ANTHROPIC_API_KEY)
    : performLocalAnalysis(hash, 'hash', parsed, enrichment);

  const mitigations = generateMitigations(hash, 'hash', parsed, enrichment);

  return {
    indicator: hash,
    type: 'hash',
    parsed,
    enrichment,
    llmAnalysis,
    mitigations,
    timestamp: new Date().toISOString(),
  };
}

// =============================================================================
// RESPONSE HELPERS
// =============================================================================

/**
 * JSON replacer that handles BigInt serialization (D1 returns BigInt for integers)
 */
function bigIntReplacer(_key: string, value: unknown): unknown {
  if (typeof value === 'bigint') {
    return Number(value);
  }
  return value;
}

function jsonResponse(data: unknown, status: number = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data, bigIntReplacer), {
    status,
    headers: {
      ...corsHeaders,
      'Content-Type': 'application/json',
      ...extraHeaders,
    },
  });
}

function errorResponse(message: string, status: number = 400): Response {
  return jsonResponse({ error: message }, status);
}

// =============================================================================
// ROUTE HANDLERS
// =============================================================================

async function handleAnalyze(
  request: Request,
  env: Env,
  _auth: AuthContext
): Promise<Response> {
  try {
    const body = (await request.json()) as AnalyzeRequest;
    const { indicator, type } = body;

    if (!indicator) {
      return errorResponse('Missing indicator', 400);
    }

    // Auto-detect type if not provided
    const detectedType = type || detectIndicatorType(indicator);

    let result: AnalysisResult;

    switch (detectedType) {
      case 'ip':
        result = await handleAnalyzeIP(indicator, env);
        break;
      case 'domain':
        result = await handleAnalyzeDomain(indicator, env);
        break;
      case 'url':
        result = await handleAnalyzeURL(indicator, env);
        break;
      case 'hash':
        result = await handleAnalyzeHash(indicator, env);
        break;
      default:
        return errorResponse('Unknown indicator type', 400);
    }

    // Store in database for audit trail
    try {
      await env.DB.prepare(
        `INSERT INTO analyses (indicator, type, result, risk_score, classification, created_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (indicator, type) DO UPDATE SET
           result = excluded.result,
           risk_score = excluded.risk_score,
           classification = excluded.classification,
           updated_at = datetime('now')`
      )
        .bind(
          indicator,
          detectedType,
          JSON.stringify(result, bigIntReplacer),
          result.llmAnalysis.riskScore,
          result.llmAnalysis.classification,
          new Date().toISOString()
        )
        .run();
    } catch (dbError) {
      // Log but don't fail the request
      console.error('Database write error:', dbError);
    }

    return jsonResponse(result);
  } catch (error) {
    console.error('Analysis error:', error);
    return errorResponse(
      error instanceof Error ? error.message : 'Internal error',
      error instanceof Error && error.message.includes('Invalid') ? 400 : 500
    );
  }
}

async function handleHealth(env: Env): Promise<Response> {
  // Basic health check
  let dbStatus = 'ok';

  try {
    await env.DB.prepare('SELECT 1').first();
  } catch {
    dbStatus = 'error';
  }

  return jsonResponse({
    status: dbStatus === 'ok' ? 'ok' : 'degraded',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    database: dbStatus,
  });
}

async function handleGetAnalysis(
  request: Request,
  env: Env
): Promise<Response> {
  const url = new URL(request.url);
  const indicator = url.searchParams.get('indicator');
  const type = url.searchParams.get('type');

  if (!indicator) {
    return errorResponse('Missing indicator parameter', 400);
  }

  try {
    const result = await env.DB.prepare(
      `SELECT * FROM analyses WHERE indicator = ? ${type ? 'AND type = ?' : ''} ORDER BY updated_at DESC LIMIT 1`
    )
      .bind(...(type ? [indicator, type] : [indicator]))
      .first<{ result: string; created_at: string; updated_at: string }>();

    if (!result) {
      return errorResponse('Analysis not found', 404);
    }

    return jsonResponse({
      ...JSON.parse(result.result),
      cachedAt: result.updated_at,
    });
  } catch (error) {
    console.error('Database read error:', error);
    return errorResponse('Internal error', 500);
  }
}

async function handleListAnalyses(
  request: Request,
  env: Env
): Promise<Response> {
  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 100);
  const offset = parseInt(url.searchParams.get('offset') || '0', 10);
  const type = url.searchParams.get('type');

  try {
    const query = type
      ? `SELECT indicator, type, risk_score, classification, created_at, updated_at FROM analyses WHERE type = ? ORDER BY updated_at DESC LIMIT ? OFFSET ?`
      : `SELECT indicator, type, risk_score, classification, created_at, updated_at FROM analyses ORDER BY updated_at DESC LIMIT ? OFFSET ?`;

    const results = await env.DB.prepare(query)
      .bind(...(type ? [type, limit, offset] : [limit, offset]))
      .all<{
        indicator: string;
        type: string;
        risk_score: number;
        classification: string;
        created_at: string;
        updated_at: string;
      }>();

    return jsonResponse({
      analyses: results.results,
      pagination: {
        limit,
        offset,
        hasMore: results.results.length === limit,
      },
    });
  } catch (error) {
    console.error('Database read error:', error);
    return errorResponse('Internal error', 500);
  }
}

// =============================================================================
// MAIN WORKER
// =============================================================================

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const startTime = Date.now();
    const url = new URL(request.url);
    const path = url.pathname;

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // Validate authentication
    const auth = await validateApiKey(request, env);

    // Public endpoints (no auth required)
    if (path === '/api/health') {
      return handleHealth(env);
    }

    // Protected endpoints
    if (!auth.isAuthenticated) {
      return unauthorizedResponse('Invalid or missing API key');
    }

    // Check rate limit
    const rateLimit = await checkRateLimit(request, env, auth);
    if (!rateLimit.allowed) {
      return rateLimitExceededResponse(rateLimit);
    }

    let response: Response;

    try {
      // Route handling
      if (path === '/api/analyze' && request.method === 'POST') {
        response = await handleAnalyze(request, env, auth);
      } else if (path === '/api/analysis' && request.method === 'GET') {
        response = await handleGetAnalysis(request, env);
      } else if (path === '/api/analyses' && request.method === 'GET') {
        response = await handleListAnalyses(request, env);
      } else {
        response = errorResponse('Not found', 404);
      }

      // Add rate limit headers
      response = addRateLimitHeaders(response, rateLimit);

      // Log access
      const duration = Date.now() - startTime;
      ctx.waitUntil(logAccess(env, auth, request, response, duration));

      return response;
    } catch (error) {
      console.error('Worker error:', error);
      return errorResponse(error instanceof Error ? error.message : 'Internal error', 500);
    }
  },
};
