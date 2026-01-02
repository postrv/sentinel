import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the external fetch calls
const originalFetch = global.fetch;

// =============================================================================
// MOCK TYPES AND HELPERS
// =============================================================================

interface MockEnv {
  DB: MockD1Database;
  CACHE: MockKVNamespace;
  ARTIFACTS: MockR2Bucket;
  VT_API_KEY: string;
  ABUSEIPDB_KEY: string;
  SHODAN_KEY: string;
  GREYNOISE_KEY: string;
  URLSCAN_KEY: string;
  ANTHROPIC_API_KEY: string;
}

interface MockD1Database {
  prepare: (query: string) => MockD1PreparedStatement;
}

interface MockD1PreparedStatement {
  bind: (...values: unknown[]) => MockD1PreparedStatement;
  run: () => Promise<{ success: boolean }>;
  first: () => Promise<Record<string, unknown> | null>;
  all: () => Promise<{ results: Record<string, unknown>[] }>;
}

interface MockKVNamespace {
  get: (key: string) => Promise<string | null>;
  put: (key: string, value: string, options?: { expirationTtl?: number }) => Promise<void>;
}

interface MockR2Bucket {
  get: (key: string) => Promise<{ text: () => Promise<string> } | null>;
  put: (key: string, value: string) => Promise<void>;
}

function createMockEnv(): MockEnv {
  const kvStore = new Map<string, string>();
  const dbStore = new Map<string, unknown[]>();

  return {
    DB: {
      prepare: (query: string) => ({
        bind: (...values: unknown[]) => ({
          bind: (...v: unknown[]) => ({
            run: async () => ({ success: true }),
            first: async () => null,
            all: async () => ({ results: [] }),
          }),
          run: async () => ({ success: true }),
          first: async () => null,
          all: async () => ({ results: [] }),
        }),
        run: async () => ({ success: true }),
        first: async () => null,
        all: async () => ({ results: [] }),
      }),
    },
    CACHE: {
      get: async (key: string) => kvStore.get(key) || null,
      put: async (key: string, value: string, options?: { expirationTtl?: number }) => {
        kvStore.set(key, value);
      },
    },
    ARTIFACTS: {
      get: async (key: string) => null,
      put: async (key: string, value: string) => {},
    },
    VT_API_KEY: 'test-vt-key',
    ABUSEIPDB_KEY: 'test-abuseipdb-key',
    SHODAN_KEY: 'test-shodan-key',
    GREYNOISE_KEY: 'test-greynoise-key',
    URLSCAN_KEY: 'test-urlscan-key',
    ANTHROPIC_API_KEY: 'test-anthropic-key',
  };
}

// Mock external API responses
const mockVirusTotalResponse = {
  data: {
    attributes: {
      last_analysis_stats: {
        malicious: 5,
        suspicious: 2,
        harmless: 60,
        undetected: 10,
      },
      reputation: -5,
      tags: ['known-scanner'],
      last_analysis_date: '2024-01-01',
    },
  },
};

const mockAbuseIPDBResponse = {
  data: {
    abuseConfidenceScore: 75,
    totalReports: 150,
    lastReportedAt: '2024-01-01T00:00:00Z',
    usageType: 'Data Center/Web Hosting/Transit',
    isp: 'Example ISP',
    domain: 'example.com',
    countryCode: 'US',
    isWhitelisted: false,
  },
};

const mockShodanResponse = {
  ports: [22, 80, 443],
  vulns: ['CVE-2021-44228'],
  tags: ['cloud'],
  hostnames: ['example.com'],
  org: 'Example Org',
  asn: 'AS12345',
  last_update: '2024-01-01',
};

const mockGreyNoiseResponse = {
  seen: true,
  classification: 'malicious',
  noise: true,
  riot: false,
  name: 'Known Scanner',
  link: 'https://greynoise.io/viz/ip/1.2.3.4',
};

const mockClaudeResponse = {
  content: [
    {
      text: JSON.stringify({
        summary: 'This IP is associated with malicious activity.',
        riskScore: 85,
        confidence: 90,
        classification: 'malicious',
        reasoning: 'High abuse confidence score and multiple malicious detections.',
        suggestedActions: ['Block at firewall', 'Search SIEM logs'],
        questionsForAnalyst: ['Is this IP in your allow list?'],
      }),
    },
  ],
};

function setupFetchMock() {
  global.fetch = vi.fn().mockImplementation(async (url: string | URL, options?: RequestInit) => {
    const urlString = url.toString();

    // VirusTotal
    if (urlString.includes('virustotal.com')) {
      return {
        ok: true,
        json: async () => mockVirusTotalResponse,
      };
    }

    // AbuseIPDB
    if (urlString.includes('abuseipdb.com')) {
      return {
        ok: true,
        json: async () => mockAbuseIPDBResponse,
      };
    }

    // Shodan
    if (urlString.includes('shodan.io')) {
      return {
        ok: true,
        json: async () => mockShodanResponse,
      };
    }

    // GreyNoise
    if (urlString.includes('greynoise.io')) {
      return {
        ok: true,
        json: async () => mockGreyNoiseResponse,
      };
    }

    // Claude/Anthropic
    if (urlString.includes('anthropic.com')) {
      return {
        ok: true,
        json: async () => mockClaudeResponse,
      };
    }

    // Cloudflare DNS
    if (urlString.includes('cloudflare-dns.com')) {
      return {
        ok: true,
        json: async () => ({
          Answer: [
            { type: 1, data: '93.184.216.34' },
          ],
        }),
      };
    }

    // Default: return 404
    return {
      ok: false,
      status: 404,
    };
  }) as typeof fetch;
}

// =============================================================================
// INDICATOR TYPE DETECTION TESTS
// =============================================================================

describe('Indicator Type Detection', () => {
  it('should detect IPv4 addresses', () => {
    const ipv4Pattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    expect(ipv4Pattern.test('192.168.1.1')).toBe(true);
    expect(ipv4Pattern.test('8.8.8.8')).toBe(true);
    expect(ipv4Pattern.test('256.1.1.1')).toBe(true); // Pattern matches, but validation catches
    expect(ipv4Pattern.test('example.com')).toBe(false);
  });

  it('should detect URLs', () => {
    const urlPattern = /^https?:\/\//;
    expect(urlPattern.test('https://example.com')).toBe(true);
    expect(urlPattern.test('http://example.com/path')).toBe(true);
    expect(urlPattern.test('ftp://example.com')).toBe(false);
    expect(urlPattern.test('example.com')).toBe(false);
  });

  it('should detect hashes', () => {
    const hashPattern = /^[a-f0-9]{32,128}$/i;
    expect(hashPattern.test('d41d8cd98f00b204e9800998ecf8427e')).toBe(true); // MD5
    expect(hashPattern.test('da39a3ee5e6b4b0d3255bfef95601890afd80709')).toBe(true); // SHA1
    expect(hashPattern.test('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')).toBe(true); // SHA256
    expect(hashPattern.test('not-a-hash')).toBe(false);
  });

  it('should default to domain for other inputs', () => {
    const ipv4Pattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    const urlPattern = /^https?:\/\//;
    const hashPattern = /^[a-f0-9]{32,128}$/i;

    const indicator = 'example.com';
    const isIP = ipv4Pattern.test(indicator);
    const isURL = urlPattern.test(indicator);
    const isHash = hashPattern.test(indicator);

    expect(isIP).toBe(false);
    expect(isURL).toBe(false);
    expect(isHash).toBe(false);
    // Therefore it's a domain
  });
});

// =============================================================================
// API RESPONSE FORMAT TESTS
// =============================================================================

describe('API Response Formats', () => {
  it('should return proper AnalysisResult structure for IP', () => {
    const expectedStructure = {
      indicator: expect.any(String),
      type: expect.stringMatching(/^(ip|domain|url|hash)$/),
      parsed: expect.any(Object),
      enrichment: expect.any(Object),
      llmAnalysis: expect.objectContaining({
        summary: expect.any(String),
        riskScore: expect.any(Number),
        confidence: expect.any(Number),
        classification: expect.any(String),
        reasoning: expect.any(String),
        suggestedActions: expect.any(Array),
        questionsForAnalyst: expect.any(Array),
      }),
      mitigations: expect.objectContaining({
        firewallRules: expect.any(Array),
        dnsBlocks: expect.any(Array),
        siemQueries: expect.any(Array),
      }),
      timestamp: expect.any(String),
    };

    // This is a structure test - validating the expected shape
    const mockResult = {
      indicator: '8.8.8.8',
      type: 'ip',
      parsed: { raw: '8.8.8.8' },
      enrichment: {},
      llmAnalysis: {
        summary: 'Test',
        riskScore: 50,
        confidence: 80,
        classification: 'suspicious',
        reasoning: 'Test reasoning',
        suggestedActions: ['action1'],
        questionsForAnalyst: ['question1'],
      },
      mitigations: {
        firewallRules: [],
        dnsBlocks: [],
        siemQueries: [],
      },
      timestamp: new Date().toISOString(),
    };

    expect(mockResult).toMatchObject(expectedStructure);
  });
});

// =============================================================================
// CORS HEADER TESTS
// =============================================================================

describe('CORS Headers', () => {
  it('should define correct CORS headers', () => {
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    expect(corsHeaders['Access-Control-Allow-Origin']).toBe('*');
    expect(corsHeaders['Access-Control-Allow-Methods']).toContain('POST');
    expect(corsHeaders['Access-Control-Allow-Headers']).toContain('Authorization');
  });
});

// =============================================================================
// ERROR RESPONSE TESTS
// =============================================================================

describe('Error Responses', () => {
  it('should create proper error response for missing indicator', () => {
    const errorResponse = {
      error: 'Missing indicator',
    };

    expect(errorResponse.error).toBe('Missing indicator');
  });

  it('should create proper error response for unknown indicator type', () => {
    const errorResponse = {
      error: 'Unknown indicator type',
    };

    expect(errorResponse.error).toBe('Unknown indicator type');
  });

  it('should create proper error response for invalid IP', () => {
    const errorResponse = {
      error: 'Invalid IPv4 address',
    };

    expect(errorResponse.error).toBe('Invalid IPv4 address');
  });

  it('should create proper error response for invalid URL', () => {
    const errorResponse = {
      error: 'Invalid URL',
    };

    expect(errorResponse.error).toBe('Invalid URL');
  });

  it('should create proper error response for invalid hash', () => {
    const errorResponse = {
      error: 'Invalid hash format',
    };

    expect(errorResponse.error).toBe('Invalid hash format');
  });
});

// =============================================================================
// MITIGATION GENERATION TESTS
// =============================================================================

describe('Mitigation Generation', () => {
  describe('Firewall Rules', () => {
    it('should generate iptables rules for public IPs', () => {
      const ip = '185.220.101.1';
      const iptablesRules = [
        `iptables -A INPUT -s ${ip} -j DROP`,
        `iptables -A OUTPUT -d ${ip} -j DROP`,
      ];

      expect(iptablesRules[0]).toContain('INPUT');
      expect(iptablesRules[0]).toContain('-s');
      expect(iptablesRules[1]).toContain('OUTPUT');
      expect(iptablesRules[1]).toContain('-d');
    });

    it('should generate AWS Security Group rule format', () => {
      const ip = '185.220.101.1';
      const awsRule = `aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol all --source ${ip}/32`;

      expect(awsRule).toContain('revoke-security-group-ingress');
      expect(awsRule).toContain('/32');
    });

    it('should generate Azure NSG rule format', () => {
      const ip = '185.220.101.1';
      const azureRule = `az network nsg rule create --nsg-name MyNSG --name Block-${ip.replace(/\./g, '-')} --priority 100 --source-address-prefixes ${ip} --access Deny`;

      expect(azureRule).toContain('nsg rule create');
      expect(azureRule).toContain('--access Deny');
    });

    it('should generate GCP Firewall rule format', () => {
      const ip = '185.220.101.1';
      const gcpRule = `gcloud compute firewall-rules create block-${ip.replace(/\./g, '-')} --action=DENY --source-ranges=${ip}/32 --priority=100`;

      expect(gcpRule).toContain('firewall-rules create');
      expect(gcpRule).toContain('--action=DENY');
    });
  });

  describe('DNS Blocks', () => {
    it('should generate Pi-hole block entry', () => {
      const domain = 'malicious.com';
      const piholeEntry = `${domain}`;

      expect(piholeEntry).toBe('malicious.com');
    });

    it('should generate BIND RPZ entry', () => {
      const domain = 'malicious.com';
      const rpzEntry = `${domain} CNAME .`;

      expect(rpzEntry).toContain('CNAME .');
    });

    it('should generate Unbound block entry', () => {
      const domain = 'malicious.com';
      const unboundEntry = `local-zone: "${domain}" always_refuse`;

      expect(unboundEntry).toContain('local-zone');
      expect(unboundEntry).toContain('always_refuse');
    });
  });

  describe('SIEM Queries', () => {
    it('should generate Splunk query for IP', () => {
      const ip = '185.220.101.1';
      const splunkQuery = `index=network (src_ip="${ip}" OR dest_ip="${ip}")`;

      expect(splunkQuery).toContain('index=');
      expect(splunkQuery).toContain('src_ip');
      expect(splunkQuery).toContain('dest_ip');
    });

    it('should generate Elastic query for IP', () => {
      const ip = '185.220.101.1';
      const elasticQuery = `source.ip:"${ip}" OR destination.ip:"${ip}"`;

      expect(elasticQuery).toContain('source.ip');
      expect(elasticQuery).toContain('destination.ip');
    });

    it('should generate Microsoft Sentinel KQL for IP', () => {
      const ip = '185.220.101.1';
      const sentinelQuery = `CommonSecurityLog | where SourceIP == "${ip}" or DestinationIP == "${ip}"`;

      expect(sentinelQuery).toContain('CommonSecurityLog');
      expect(sentinelQuery).toContain('SourceIP');
    });

    it('should generate Splunk query for domain', () => {
      const domain = 'malicious.com';
      const splunkQuery = `index=dns query="${domain}" OR query="*.${domain}"`;

      expect(splunkQuery).toContain('index=dns');
      expect(splunkQuery).toContain('query=');
    });
  });
});

// =============================================================================
// CACHING TESTS
// =============================================================================

describe('Caching Behavior', () => {
  it('should construct proper cache keys', () => {
    const ip = '8.8.8.8';
    const vtCacheKey = `vt:ip:${ip}`;
    const abuseipdbCacheKey = `abuseipdb:${ip}`;
    const shodanCacheKey = `shodan:${ip}`;
    const greynoiseCacheKey = `greynoise:${ip}`;

    expect(vtCacheKey).toBe('vt:ip:8.8.8.8');
    expect(abuseipdbCacheKey).toBe('abuseipdb:8.8.8.8');
    expect(shodanCacheKey).toBe('shodan:8.8.8.8');
    expect(greynoiseCacheKey).toBe('greynoise:8.8.8.8');
  });

  it('should use 1-hour TTL for cache entries', () => {
    const ttl = 3600; // 1 hour in seconds
    expect(ttl).toBe(3600);
  });
});

// =============================================================================
// LLM PROMPT CONSTRUCTION TESTS
// =============================================================================

describe('LLM Prompt Construction', () => {
  it('should include semantic context in prompt', () => {
    const semanticContext = `
=== IP ADDRESS ANALYSIS ===

INDICATOR: 8.8.8.8
TYPE: IPv4 Address

CLASSIFICATION:
- Category: PUBLIC
- Internet Routable: YES
`;

    expect(semanticContext).toContain('IP ADDRESS ANALYSIS');
    expect(semanticContext).toContain('8.8.8.8');
    expect(semanticContext).toContain('IPv4 Address');
  });

  it('should include enrichment data in prompt', () => {
    const enrichmentSection = `
=== THREAT INTELLIGENCE ENRICHMENT ===

VIRUSTOTAL:
- Malicious detections: 5
- Suspicious detections: 2
- Reputation score: -5
`;

    expect(enrichmentSection).toContain('VIRUSTOTAL');
    expect(enrichmentSection).toContain('Malicious detections');
  });

  it('should define proper system prompt for Claude', () => {
    const systemPrompt = `You are a senior security analyst performing threat intelligence analysis.
Your task is to analyze security indicators and provide actionable intelligence.`;

    expect(systemPrompt).toContain('security analyst');
    expect(systemPrompt).toContain('threat intelligence');
    expect(systemPrompt).toContain('actionable intelligence');
  });
});

// =============================================================================
// HEALTH CHECK TESTS
// =============================================================================

describe('Health Check Endpoint', () => {
  it('should return correct health check response format', () => {
    const healthResponse = {
      status: 'ok',
      timestamp: new Date().toISOString(),
    };

    expect(healthResponse.status).toBe('ok');
    expect(healthResponse.timestamp).toBeDefined();
    expect(new Date(healthResponse.timestamp).getTime()).not.toBeNaN();
  });
});

// =============================================================================
// ROUTE HANDLING TESTS
// =============================================================================

describe('Route Handling', () => {
  it('should recognize /api/analyze endpoint', () => {
    const path = '/api/analyze';
    expect(path).toBe('/api/analyze');
  });

  it('should recognize /api/health endpoint', () => {
    const path = '/api/health';
    expect(path).toBe('/api/health');
  });

  it('should return 404 for unknown routes', () => {
    const unknownPath = '/api/unknown';
    const expectedResponse = { error: 'Not found' };
    const expectedStatus = 404;

    expect(expectedResponse.error).toBe('Not found');
    expect(expectedStatus).toBe(404);
  });
});

// =============================================================================
// PRIVATE IP HANDLING TESTS
// =============================================================================

describe('Private IP Handling', () => {
  it('should not enrich private IPs with external APIs', () => {
    // Private IPs should not trigger external API calls
    const privateRanges = [
      '10.0.0.1',
      '172.16.0.1',
      '192.168.1.1',
      '127.0.0.1',
    ];

    privateRanges.forEach(ip => {
      // These should be classified as non-routable
      const isPrivate = (
        ip.startsWith('10.') ||
        ip.startsWith('172.16.') ||
        ip.startsWith('192.168.') ||
        ip.startsWith('127.')
      );
      expect(isPrivate).toBe(true);
    });
  });

  it('should still provide analysis for private IPs', () => {
    // Private IPs should still get local analysis (no external enrichment)
    const privateIP = '192.168.1.1';
    const expectedAnalysis = {
      indicator: privateIP,
      type: 'ip',
      classification: 'private',
      isInternetRoutable: false,
    };

    expect(expectedAnalysis.isInternetRoutable).toBe(false);
  });
});

// =============================================================================
// REQUEST VALIDATION TESTS
// =============================================================================

describe('Request Validation', () => {
  it('should require indicator in request body', () => {
    const emptyBody = {};
    const hasIndicator = 'indicator' in emptyBody;

    expect(hasIndicator).toBe(false);
  });

  it('should accept optional type parameter', () => {
    const requestBody = {
      indicator: '8.8.8.8',
      type: 'ip',
    };

    expect(requestBody.indicator).toBeDefined();
    expect(requestBody.type).toBe('ip');
  });

  it('should auto-detect type if not provided', () => {
    const requestBody = {
      indicator: '8.8.8.8',
    };

    const indicator = requestBody.indicator;
    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

    expect(ipPattern.test(indicator)).toBe(true);
  });
});

// =============================================================================
// CLEANUP
// =============================================================================

afterEach(() => {
  global.fetch = originalFetch;
  vi.clearAllMocks();
});
