/**
 * Sentinel Type Definitions
 *
 * Central type definitions for the Sentinel platform.
 */

import type { ParsedIP, DomainStructure, URLAnalysis, HashAnalysis } from './lib/indicators';

// =============================================================================
// ENVIRONMENT TYPES
// =============================================================================

export interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  ARTIFACTS: R2Bucket;
  VT_API_KEY: string;
  ABUSEIPDB_KEY: string;
  SHODAN_KEY: string;
  GREYNOISE_KEY: string;
  URLSCAN_KEY: string;
  ANTHROPIC_API_KEY: string;
  API_SECRET_KEY?: string;
}

// =============================================================================
// ANALYSIS TYPES
// =============================================================================

export type IndicatorType = 'ip' | 'domain' | 'url' | 'hash';

export interface AnalysisResult {
  indicator: string;
  type: IndicatorType;
  parsed: ParsedIP | DomainStructure | URLAnalysis | HashAnalysis;
  enrichment: EnrichmentData;
  llmAnalysis: LLMAnalysis;
  mitigations: Mitigations;
  timestamp: string;
}

export interface EnrichmentData {
  virustotal?: VTResponse;
  abuseipdb?: AbuseIPDBResponse;
  shodan?: ShodanResponse;
  greynoise?: GreyNoiseResponse;
  urlscan?: URLScanResponse;
  whois?: WhoisResponse;
  dns?: DNSResponse;
}

export interface LLMAnalysis {
  summary: string;
  riskScore: number;
  confidence: number;
  classification: string;
  reasoning: string;
  suggestedActions: string[];
  questionsForAnalyst: string[];
}

export interface Mitigations {
  firewallRules: string[];
  dnsBlocks: string[];
  siemQueries: string[];
  k8sNetworkPolicies?: string[];
}

// =============================================================================
// EXTERNAL API RESPONSE TYPES
// =============================================================================

export interface VTResponse {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  lastAnalysisDate: string;
  reputation: number;
  tags: string[];
}

export interface AbuseIPDBResponse {
  abuseConfidenceScore: number;
  totalReports: number;
  lastReportedAt: string | null;
  usageType: string;
  isp: string;
  domain: string;
  countryCode: string;
  isWhitelisted: boolean;
}

export interface ShodanResponse {
  ports: number[];
  vulns: string[];
  tags: string[];
  hostnames: string[];
  org: string;
  asn: string;
  lastUpdate: string;
}

export interface GreyNoiseResponse {
  seen: boolean;
  classification: 'benign' | 'malicious' | 'unknown';
  noise: boolean;
  riot: boolean;
  name: string;
  link: string;
}

export interface URLScanResponse {
  verdicts: {
    overall: { malicious: boolean; score: number };
    engines: { malicious: number; suspicious: number };
  };
  page: {
    url: string;
    domain: string;
    ip: string;
    country: string;
    server: string;
  };
  screenshotUrl: string;
}

export interface WhoisResponse {
  registrar: string;
  createdDate: string;
  expiresDate: string;
  nameservers: string[];
  registrantOrg: string;
  privacyProtected: boolean;
}

export interface DNSResponse {
  a: string[];
  aaaa: string[];
  mx: string[];
  txt: string[];
  ns: string[];
  cname: string | null;
}

// =============================================================================
// REQUEST/RESPONSE TYPES
// =============================================================================

export interface AnalyzeRequest {
  indicator: string;
  type?: IndicatorType;
}

export interface ErrorResponse {
  error: string;
  details?: string;
}

export interface HealthResponse {
  status: 'ok' | 'degraded' | 'error';
  timestamp: string;
  version?: string;
}

// =============================================================================
// AUTH TYPES
// =============================================================================

export interface AuthContext {
  isAuthenticated: boolean;
  apiKeyId?: number;
  permissions?: string[];
  rateLimitPerMinute?: number;
  rateLimitPerDay?: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  retryAfter?: number;
}

// =============================================================================
// RE-EXPORT INDICATOR TYPES
// =============================================================================

export type { ParsedIP, DomainStructure, URLAnalysis, HashAnalysis };
