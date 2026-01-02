/**
 * Enrichment Service
 *
 * Handles external threat intelligence API queries with caching and graceful degradation.
 */

import type {
  Env,
  VTResponse,
  AbuseIPDBResponse,
  ShodanResponse,
  GreyNoiseResponse,
  DNSResponse,
  EnrichmentData,
  IndicatorType,
} from '../types';

// Cache TTL in seconds (1 hour)
const CACHE_TTL = 3600;

// =============================================================================
// VIRUSTOTAL
// =============================================================================

export async function queryVirusTotal(
  indicator: string,
  type: IndicatorType,
  apiKey: string,
  cache: KVNamespace
): Promise<VTResponse | null> {
  const cacheKey = `vt:${type}:${indicator}`;

  // Check cache first
  const cached = await cache.get(cacheKey);
  if (cached) {
    try {
      return JSON.parse(cached);
    } catch {
      // Invalid cache, continue to fetch
    }
  }

  try {
    let endpoint: string;
    let body: string | null = null;
    let method = 'GET';

    switch (type) {
      case 'ip':
        endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${indicator}`;
        break;
      case 'domain':
        endpoint = `https://www.virustotal.com/api/v3/domains/${indicator}`;
        break;
      case 'url':
        endpoint = `https://www.virustotal.com/api/v3/urls`;
        method = 'POST';
        body = `url=${encodeURIComponent(indicator)}`;
        break;
      case 'hash':
        endpoint = `https://www.virustotal.com/api/v3/files/${indicator}`;
        break;
      default:
        return null;
    }

    const response = await fetch(endpoint, {
      method,
      headers: {
        'x-apikey': apiKey,
        ...(body ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {}),
      },
      ...(body ? { body } : {}),
    });

    if (!response.ok) {
      console.error(`VT API error: ${response.status}`);
      return null;
    }

    const data = (await response.json()) as {
      data?: {
        attributes?: {
          last_analysis_stats?: Record<string, number>;
          last_analysis_date?: string;
          reputation?: number;
          tags?: string[];
        };
      };
    };

    const stats = data.data?.attributes?.last_analysis_stats || {};

    const result: VTResponse = {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      lastAnalysisDate: data.data?.attributes?.last_analysis_date || '',
      reputation: data.data?.attributes?.reputation || 0,
      tags: data.data?.attributes?.tags || [],
    };

    // Cache for 1 hour
    await cache.put(cacheKey, JSON.stringify(result), { expirationTtl: CACHE_TTL });

    return result;
  } catch (error) {
    console.error('VT query failed:', error);
    return null;
  }
}

// =============================================================================
// ABUSEIPDB
// =============================================================================

export async function queryAbuseIPDB(
  ip: string,
  apiKey: string,
  cache: KVNamespace
): Promise<AbuseIPDBResponse | null> {
  const cacheKey = `abuseipdb:${ip}`;

  const cached = await cache.get(cacheKey);
  if (cached) {
    try {
      return JSON.parse(cached);
    } catch {
      // Invalid cache, continue to fetch
    }
  }

  try {
    const response = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      {
        headers: {
          Key: apiKey,
          Accept: 'application/json',
        },
      }
    );

    if (!response.ok) {
      console.error(`AbuseIPDB API error: ${response.status}`);
      return null;
    }

    const data = (await response.json()) as {
      data?: {
        abuseConfidenceScore?: number;
        totalReports?: number;
        lastReportedAt?: string | null;
        usageType?: string;
        isp?: string;
        domain?: string;
        countryCode?: string;
        isWhitelisted?: boolean;
      };
    };

    const result: AbuseIPDBResponse = {
      abuseConfidenceScore: data.data?.abuseConfidenceScore || 0,
      totalReports: data.data?.totalReports || 0,
      lastReportedAt: data.data?.lastReportedAt || null,
      usageType: data.data?.usageType || 'Unknown',
      isp: data.data?.isp || 'Unknown',
      domain: data.data?.domain || '',
      countryCode: data.data?.countryCode || '',
      isWhitelisted: data.data?.isWhitelisted || false,
    };

    await cache.put(cacheKey, JSON.stringify(result), { expirationTtl: CACHE_TTL });

    return result;
  } catch (error) {
    console.error('AbuseIPDB query failed:', error);
    return null;
  }
}

// =============================================================================
// SHODAN
// =============================================================================

export async function queryShodan(
  ip: string,
  apiKey: string,
  cache: KVNamespace
): Promise<ShodanResponse | null> {
  const cacheKey = `shodan:${ip}`;

  const cached = await cache.get(cacheKey);
  if (cached) {
    try {
      return JSON.parse(cached);
    } catch {
      // Invalid cache, continue to fetch
    }
  }

  try {
    const response = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`);

    if (!response.ok) {
      if (response.status === 404) {
        // No data for this IP - cache the negative result
        const emptyResult: ShodanResponse = {
          ports: [],
          vulns: [],
          tags: [],
          hostnames: [],
          org: '',
          asn: '',
          lastUpdate: '',
        };
        await cache.put(cacheKey, JSON.stringify(emptyResult), { expirationTtl: CACHE_TTL });
        return emptyResult;
      }
      console.error(`Shodan API error: ${response.status}`);
      return null;
    }

    const data = (await response.json()) as {
      ports?: number[];
      vulns?: string[];
      tags?: string[];
      hostnames?: string[];
      org?: string;
      asn?: string;
      last_update?: string;
    };

    const result: ShodanResponse = {
      ports: data.ports || [],
      vulns: data.vulns || [],
      tags: data.tags || [],
      hostnames: data.hostnames || [],
      org: data.org || '',
      asn: data.asn || '',
      lastUpdate: data.last_update || '',
    };

    await cache.put(cacheKey, JSON.stringify(result), { expirationTtl: CACHE_TTL });

    return result;
  } catch (error) {
    console.error('Shodan query failed:', error);
    return null;
  }
}

// =============================================================================
// GREYNOISE
// =============================================================================

export async function queryGreyNoise(
  ip: string,
  apiKey: string,
  cache: KVNamespace
): Promise<GreyNoiseResponse | null> {
  const cacheKey = `greynoise:${ip}`;

  const cached = await cache.get(cacheKey);
  if (cached) {
    try {
      return JSON.parse(cached);
    } catch {
      // Invalid cache, continue to fetch
    }
  }

  try {
    const response = await fetch(`https://api.greynoise.io/v3/community/${ip}`, {
      headers: {
        key: apiKey,
      },
    });

    if (!response.ok) {
      console.error(`GreyNoise API error: ${response.status}`);
      return null;
    }

    const data = (await response.json()) as {
      seen?: boolean;
      classification?: 'benign' | 'malicious' | 'unknown';
      noise?: boolean;
      riot?: boolean;
      name?: string;
      link?: string;
    };

    const result: GreyNoiseResponse = {
      seen: data.seen || false,
      classification: data.classification || 'unknown',
      noise: data.noise || false,
      riot: data.riot || false,
      name: data.name || '',
      link: data.link || '',
    };

    await cache.put(cacheKey, JSON.stringify(result), { expirationTtl: CACHE_TTL });

    return result;
  } catch (error) {
    console.error('GreyNoise query failed:', error);
    return null;
  }
}

// =============================================================================
// DNS LOOKUP
// =============================================================================

export async function queryDNS(domain: string): Promise<DNSResponse> {
  const result: DNSResponse = {
    a: [],
    aaaa: [],
    mx: [],
    txt: [],
    ns: [],
    cname: null,
  };

  try {
    const types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'];

    await Promise.all(
      types.map(async type => {
        try {
          const response = await fetch(
            `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`,
            {
              headers: {
                Accept: 'application/dns-json',
              },
            }
          );

          if (response.ok) {
            const data = (await response.json()) as {
              Answer?: Array<{ type: number; data: string }>;
            };
            const answers = data.Answer || [];

            for (const answer of answers) {
              switch (answer.type) {
                case 1:
                  result.a.push(answer.data);
                  break;
                case 28:
                  result.aaaa.push(answer.data);
                  break;
                case 15:
                  result.mx.push(answer.data);
                  break;
                case 16:
                  result.txt.push(answer.data);
                  break;
                case 2:
                  result.ns.push(answer.data);
                  break;
                case 5:
                  result.cname = answer.data;
                  break;
              }
            }
          }
        } catch {
          // Ignore individual DNS query failures
        }
      })
    );
  } catch (error) {
    console.error('DNS query failed:', error);
  }

  return result;
}

// =============================================================================
// AGGREGATED ENRICHMENT
// =============================================================================

export async function enrichIP(ip: string, env: Env): Promise<EnrichmentData> {
  const [vt, abuseipdb, shodan, greynoise] = await Promise.all([
    queryVirusTotal(ip, 'ip', env.VT_API_KEY, env.CACHE),
    queryAbuseIPDB(ip, env.ABUSEIPDB_KEY, env.CACHE),
    queryShodan(ip, env.SHODAN_KEY, env.CACHE),
    queryGreyNoise(ip, env.GREYNOISE_KEY, env.CACHE),
  ]);

  return {
    virustotal: vt || undefined,
    abuseipdb: abuseipdb || undefined,
    shodan: shodan || undefined,
    greynoise: greynoise || undefined,
  };
}

export async function enrichDomain(domain: string, env: Env): Promise<EnrichmentData> {
  const [vt, dns] = await Promise.all([
    queryVirusTotal(domain, 'domain', env.VT_API_KEY, env.CACHE),
    queryDNS(domain),
  ]);

  return {
    virustotal: vt || undefined,
    dns,
  };
}

export async function enrichURL(url: string, domain: string, env: Env): Promise<EnrichmentData> {
  const [vt, dns] = await Promise.all([
    queryVirusTotal(url, 'url', env.VT_API_KEY, env.CACHE),
    queryDNS(domain),
  ]);

  return {
    virustotal: vt || undefined,
    dns,
  };
}

export async function enrichHash(hash: string, env: Env): Promise<EnrichmentData> {
  const vt = await queryVirusTotal(hash, 'hash', env.VT_API_KEY, env.CACHE);

  return {
    virustotal: vt || undefined,
  };
}
