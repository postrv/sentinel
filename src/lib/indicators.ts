/**
 * Sentinel Core Library
 * 
 * Provides LLM-aware preprocessing for security indicators.
 * The key insight is that LLMs tokenize IPs and domains poorly,
 * so we pre-compute classifications and semantic descriptions.
 */

// ============================================================================
// IP ADDRESS HANDLING
// ============================================================================

interface IPClassification {
  type: 'public' | 'private' | 'loopback' | 'link-local' | 'multicast' | 
        'broadcast' | 'cgnat' | 'documentation' | 'reserved' | 'invalid';
  rfc: string | null;
  cidr: string;
  humanDescription: string;
  isInternetRoutable: boolean;
  securityImplications: string;
}

interface ParsedIP {
  raw: string;
  version: 4 | 6;
  octets: number[];          // For IPv4
  segments: string[];        // For IPv6
  decimal: bigint;           // Numeric representation
  binary: string;            // Binary string
  hex: string;               // Hex representation
  classification: IPClassification;
  semanticContext: string;   // Pre-built context for LLM
}

// IPv4 CIDR ranges and their classifications
const IPV4_RANGES: Array<{
  cidr: string;
  start: number;
  end: number;
  classification: Omit<IPClassification, 'cidr'>;
}> = [
  {
    cidr: '0.0.0.0/8',
    start: 0,
    end: 16777215,
    classification: {
      type: 'reserved',
      rfc: 'RFC1122',
      humanDescription: 'Current network (only valid as source address)',
      isInternetRoutable: false,
      securityImplications: 'If seen as destination, indicates misconfiguration or spoofing attempt'
    }
  },
  {
    cidr: '10.0.0.0/8',
    start: 167772160,
    end: 184549375,
    classification: {
      type: 'private',
      rfc: 'RFC1918',
      humanDescription: 'Private network - Class A (large enterprise LANs)',
      isInternetRoutable: false,
      securityImplications: 'Internal network address. If seen in external traffic, indicates NAT issue or header injection'
    }
  },
  {
    cidr: '100.64.0.0/10',
    start: 1681915904,
    end: 1686110207,
    classification: {
      type: 'cgnat',
      rfc: 'RFC6598',
      humanDescription: 'Carrier-Grade NAT (shared address space for ISPs)',
      isInternetRoutable: false,
      securityImplications: 'ISP-level NAT. Cannot reliably attribute to single subscriber'
    }
  },
  {
    cidr: '127.0.0.0/8',
    start: 2130706432,
    end: 2147483647,
    classification: {
      type: 'loopback',
      rfc: 'RFC1122',
      humanDescription: 'Localhost/loopback (refers to this machine)',
      isInternetRoutable: false,
      securityImplications: 'Should never appear in network traffic. If seen, indicates SSRF attempt or misconfiguration'
    }
  },
  {
    cidr: '169.254.0.0/16',
    start: 2851995648,
    end: 2852061183,
    classification: {
      type: 'link-local',
      rfc: 'RFC3927',
      humanDescription: 'Link-local (APIPA - automatic private IP addressing)',
      isInternetRoutable: false,
      securityImplications: 'Auto-assigned when DHCP fails. Indicates network connectivity issues'
    }
  },
  {
    cidr: '172.16.0.0/12',
    start: 2886729728,
    end: 2887778303,
    classification: {
      type: 'private',
      rfc: 'RFC1918',
      humanDescription: 'Private network - Class B (medium enterprise LANs)',
      isInternetRoutable: false,
      securityImplications: 'Internal network address. Common in corporate environments'
    }
  },
  {
    cidr: '192.0.0.0/24',
    start: 3221225472,
    end: 3221225727,
    classification: {
      type: 'reserved',
      rfc: 'RFC6890',
      humanDescription: 'IETF Protocol Assignments',
      isInternetRoutable: false,
      securityImplications: 'Reserved for protocol use. Should not appear in normal traffic'
    }
  },
  {
    cidr: '192.0.2.0/24',
    start: 3221225984,
    end: 3221226239,
    classification: {
      type: 'documentation',
      rfc: 'RFC5737',
      humanDescription: 'Documentation (TEST-NET-1) - for examples only',
      isInternetRoutable: false,
      securityImplications: 'Example IP range. If seen in production, indicates copy-paste from documentation'
    }
  },
  {
    cidr: '192.88.99.0/24',
    start: 3227017984,
    end: 3227018239,
    classification: {
      type: 'reserved',
      rfc: 'RFC7526',
      humanDescription: '6to4 Relay Anycast (deprecated)',
      isInternetRoutable: true,
      securityImplications: 'Legacy IPv6 transition mechanism. May indicate outdated infrastructure'
    }
  },
  {
    cidr: '192.168.0.0/16',
    start: 3232235520,
    end: 3232301055,
    classification: {
      type: 'private',
      rfc: 'RFC1918',
      humanDescription: 'Private network - Class C (home networks, small offices)',
      isInternetRoutable: false,
      securityImplications: 'Most common home network range. If seen externally, indicates NAT misconfiguration'
    }
  },
  {
    cidr: '198.18.0.0/15',
    start: 3323068416,
    end: 3323199487,
    classification: {
      type: 'reserved',
      rfc: 'RFC2544',
      humanDescription: 'Benchmarking (network device testing)',
      isInternetRoutable: false,
      securityImplications: 'Used for performance testing. Should not appear in production'
    }
  },
  {
    cidr: '198.51.100.0/24',
    start: 3325256704,
    end: 3325256959,
    classification: {
      type: 'documentation',
      rfc: 'RFC5737',
      humanDescription: 'Documentation (TEST-NET-2) - for examples only',
      isInternetRoutable: false,
      securityImplications: 'Example IP range. If seen in production, indicates configuration error'
    }
  },
  {
    cidr: '203.0.113.0/24',
    start: 3405803776,
    end: 3405804031,
    classification: {
      type: 'documentation',
      rfc: 'RFC5737',
      humanDescription: 'Documentation (TEST-NET-3) - for examples only',
      isInternetRoutable: false,
      securityImplications: 'Example IP range. If seen in production, indicates configuration error'
    }
  },
  {
    cidr: '224.0.0.0/4',
    start: 3758096384,
    end: 4026531839,
    classification: {
      type: 'multicast',
      rfc: 'RFC5771',
      humanDescription: 'Multicast addresses (one-to-many communication)',
      isInternetRoutable: false,
      securityImplications: 'Used for group communication. Unusual in standard web traffic'
    }
  },
  {
    cidr: '240.0.0.0/4',
    start: 4026531840,
    end: 4294967294,
    classification: {
      type: 'reserved',
      rfc: 'RFC1112',
      humanDescription: 'Reserved for future use',
      isInternetRoutable: false,
      securityImplications: 'Should not be in use. If seen, indicates spoofing or misconfiguration'
    }
  },
  {
    cidr: '255.255.255.255/32',
    start: 4294967295,
    end: 4294967295,
    classification: {
      type: 'broadcast',
      rfc: 'RFC919',
      humanDescription: 'Limited broadcast address',
      isInternetRoutable: false,
      securityImplications: 'Local network broadcast. Should not appear in routed traffic'
    }
  }
];

export function parseIPv4(ip: string): ParsedIP | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  
  const octets = parts.map(p => parseInt(p, 10));
  if (octets.some(o => isNaN(o) || o < 0 || o > 255)) return null;
  
  const decimal = BigInt(
    (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
  ) & BigInt(0xFFFFFFFF);
  
  const decimalNum = Number(decimal);
  
  // Find matching range
  let classification: IPClassification = {
    type: 'public',
    rfc: null,
    cidr: 'N/A',
    humanDescription: 'Public internet address',
    isInternetRoutable: true,
    securityImplications: 'Publicly routable. Can be attributed and investigated via OSINT'
  };
  
  for (const range of IPV4_RANGES) {
    if (decimalNum >= range.start && decimalNum <= range.end) {
      classification = { ...range.classification, cidr: range.cidr };
      break;
    }
  }
  
  // Build semantic context for LLM
  const semanticContext = buildIPSemanticContext(ip, octets, decimal, classification);
  
  return {
    raw: ip,
    version: 4,
    octets,
    segments: [],
    decimal,
    binary: decimal.toString(2).padStart(32, '0'),
    hex: '0x' + decimal.toString(16).padStart(8, '0'),
    classification,
    semanticContext
  };
}

function buildIPSemanticContext(
  ip: string, 
  octets: number[], 
  decimal: bigint, 
  classification: IPClassification
): string {
  return `
=== IP ADDRESS ANALYSIS ===

INDICATOR: ${ip}
TYPE: IPv4 Address

NUMERIC REPRESENTATIONS:
- Dotted decimal: ${ip}
- Integer: ${decimal.toString()}
- Hexadecimal: 0x${decimal.toString(16).padStart(8, '0')}
- Octet breakdown: [${octets.join(', ')}]

CLASSIFICATION:
- Category: ${classification.type.toUpperCase()}
- CIDR Block: ${classification.cidr}
- RFC: ${classification.rfc || 'N/A'}
- Internet Routable: ${classification.isInternetRoutable ? 'YES' : 'NO'}

HUMAN-READABLE MEANING:
${classification.humanDescription}

SECURITY IMPLICATIONS:
${classification.securityImplications}

=== END IP ANALYSIS ===
`.trim();
}

// ============================================================================
// DOMAIN HANDLING
// ============================================================================

interface DomainStructure {
  raw: string;
  normalized: string;
  isPunycode: boolean;
  decodedUnicode: string | null;
  parts: string[];
  tld: string;
  sld: string;
  subdomain: string | null;
  depth: number;
  entropy: number;
  length: number;
  hasNumbers: boolean;
  hasDashes: boolean;
  hasUnderscores: boolean;
  looksLikeDGA: boolean;
  homoglyphTarget: string | null;
  semanticContext: string;
}

// High-risk TLDs (commonly abused)
const HIGH_RISK_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq',  // Free TLDs
  'xyz', 'top', 'club', 'online', 'site', 'website',  // Cheap TLDs
  'buzz', 'surf', 'cam', 'icu',  // Known spam TLDs
  'ru', 'cn', 'su',  // High abuse rates
  'zip', 'mov',  // Confusing TLDs
]);

// Trusted TLDs (lower suspicion)
const TRUSTED_TLDS = new Set([
  'gov', 'mil', 'edu',  // Government/military/education
  'bank', 'insurance',  // Verified industries
  'apple', 'google', 'microsoft', 'amazon',  // Brand TLDs
]);

// Suspicious TLD (neutral, but context matters)
const NEUTRAL_TLDS = new Set([
  'com', 'net', 'org', 'io', 'co', 'dev', 'app'
]);

export function parseDomain(domain: string): DomainStructure {
  const normalized = domain.toLowerCase().trim();
  
  // Check for punycode
  const isPunycode = normalized.includes('xn--');
  let decodedUnicode: string | null = null;
  
  if (isPunycode) {
    try {
      // In a real implementation, use punycode library
      decodedUnicode = decodePunycode(normalized);
    } catch {
      decodedUnicode = null;
    }
  }
  
  // Split into parts
  const parts = normalized.split('.');
  const tld = parts[parts.length - 1] || '';
  const sld = parts[parts.length - 2] || '';
  const subdomain = parts.length > 2 ? parts.slice(0, -2).join('.') : null;
  
  // Calculate entropy (for DGA detection)
  const entropy = calculateEntropy(sld);
  
  // Pattern analysis
  const hasNumbers = /\d/.test(sld);
  const hasDashes = sld.includes('-');
  const hasUnderscores = sld.includes('_');
  
  // DGA heuristics
  const looksLikeDGA = entropy > 3.5 && sld.length > 10 && hasNumbers;
  
  // Homoglyph detection
  const homoglyphTarget = detectHomoglyph(normalized);
  
  // TLD reputation
  const tldReputation = HIGH_RISK_TLDS.has(tld) ? 'high-risk' :
                        TRUSTED_TLDS.has(tld) ? 'trusted' :
                        NEUTRAL_TLDS.has(tld) ? 'neutral' : 'unknown';
  
  // Build semantic context
  const semanticContext = buildDomainSemanticContext({
    raw: domain,
    normalized,
    isPunycode,
    decodedUnicode,
    parts,
    tld,
    tldReputation,
    sld,
    subdomain,
    entropy,
    hasNumbers,
    hasDashes,
    looksLikeDGA,
    homoglyphTarget
  });
  
  return {
    raw: domain,
    normalized,
    isPunycode,
    decodedUnicode,
    parts,
    tld,
    sld,
    subdomain,
    depth: parts.length,
    entropy,
    length: sld.length,
    hasNumbers,
    hasDashes,
    hasUnderscores,
    looksLikeDGA,
    homoglyphTarget,
    semanticContext
  };
}

function calculateEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  
  let entropy = 0;
  const len = str.length;
  
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  
  return Math.round(entropy * 100) / 100;
}

// Simplified punycode decoder (real impl would use proper library)
function decodePunycode(domain: string): string {
  // This is a placeholder - real implementation would use punycode library
  return domain.replace(/xn--/g, '[PUNYCODE:]');
}

// Homoglyph detection - check for lookalike domains
const BRAND_TARGETS = ['apple', 'google', 'microsoft', 'amazon', 'paypal', 'netflix', 'facebook', 'instagram', 'twitter', 'linkedin', 'dropbox', 'github', 'slack'];

const HOMOGLYPHS: Record<string, string[]> = {
  'a': ['а', 'ạ', 'ą', 'à', 'á', 'â', 'ã', 'ä', 'å', 'α', '@'],
  'e': ['е', 'ė', 'ę', 'è', 'é', 'ê', 'ë', 'ε', '3'],
  'i': ['і', 'ì', 'í', 'î', 'ï', 'ι', '1', 'l', '|'],
  'o': ['о', 'ọ', 'ø', 'ò', 'ó', 'ô', 'õ', 'ö', 'ο', '0'],
  'u': ['υ', 'ù', 'ú', 'û', 'ü'],
  'c': ['с', 'ç', '('],
  'p': ['р', 'ρ'],
  's': ['ѕ', '$', '5'],
  'x': ['х', '×'],
  'y': ['у', 'ý', 'ÿ'],
  'n': ['п', 'ñ'],
  'l': ['1', 'i', '|', 'ӏ'],
  'g': ['ɡ', '9'],
  'k': ['κ'],
  't': ['τ', '+'],
  'w': ['ш', 'ω'],
  'm': ['м', 'rn'],
  'h': ['һ'],
  'd': ['ԁ'],
  'b': ['ь', '6'],
};

function detectHomoglyph(domain: string): string | null {
  const sld = domain.split('.').slice(-2, -1)[0] || '';
  const normalized = normalizeHomoglyphs(sld);
  
  for (const brand of BRAND_TARGETS) {
    // Direct match after normalization
    if (normalized === brand && sld !== brand) {
      return brand;
    }
    
    // Levenshtein distance check
    if (levenshteinDistance(normalized, brand) <= 2 && sld !== brand) {
      return brand;
    }
    
    // Contains brand with extra chars
    if (normalized.includes(brand) && normalized !== brand) {
      return brand;
    }
  }
  
  return null;
}

function normalizeHomoglyphs(str: string): string {
  let result = str.toLowerCase();
  
  for (const [ascii, lookalikes] of Object.entries(HOMOGLYPHS)) {
    for (const lookalike of lookalikes) {
      result = result.replaceAll(lookalike, ascii);
    }
  }
  
  // Handle common substitutions
  result = result.replace(/rn/g, 'm');  // rn looks like m
  result = result.replace(/vv/g, 'w');  // vv looks like w
  
  return result;
}

function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];
  
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }
  
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  
  return matrix[b.length][a.length];
}

function buildDomainSemanticContext(data: {
  raw: string;
  normalized: string;
  isPunycode: boolean;
  decodedUnicode: string | null;
  parts: string[];
  tld: string;
  tldReputation: string;
  sld: string;
  subdomain: string | null;
  entropy: number;
  hasNumbers: boolean;
  hasDashes: boolean;
  looksLikeDGA: boolean;
  homoglyphTarget: string | null;
}): string {
  let context = `
=== DOMAIN ANALYSIS ===

INDICATOR: ${data.raw}
TYPE: Domain Name

STRUCTURE:
- Full domain: ${data.normalized}
- TLD (Top-Level Domain): .${data.tld}
- SLD (Second-Level Domain): ${data.sld}
- Subdomain: ${data.subdomain || 'None'}
- Depth: ${data.parts.length} levels

TLD ANALYSIS:
- TLD: .${data.tld}
- Reputation Category: ${data.tldReputation.toUpperCase()}
`;

  if (data.isPunycode) {
    context += `
INTERNATIONALIZED DOMAIN (IDN):
- Contains Punycode: YES (xn-- prefix detected)
- Unicode representation: ${data.decodedUnicode || 'Unable to decode'}
- WARNING: IDN domains can be used for homoglyph/lookalike attacks
`;
  }

  if (data.homoglyphTarget) {
    context += `
⚠️ HOMOGLYPH ATTACK DETECTED:
- This domain appears to impersonate: ${data.homoglyphTarget.toUpperCase()}
- Attack type: Visual lookalike/typosquatting
- Risk: HIGH - Likely phishing infrastructure
`;
  }

  context += `
ENTROPY ANALYSIS:
- Shannon entropy of SLD: ${data.entropy}
- Interpretation: ${
  data.entropy < 2.5 ? 'Low entropy (normal word-like domain)' :
  data.entropy < 3.5 ? 'Medium entropy (mixed characters)' :
  'High entropy (random-looking, possible DGA)'
}

PATTERN ANALYSIS:
- Contains numbers: ${data.hasNumbers ? 'YES' : 'NO'}
- Contains dashes: ${data.hasDashes ? 'YES' : 'NO'}
- SLD length: ${data.sld.length} characters
- Looks like DGA: ${data.looksLikeDGA ? 'YES - High entropy + length + numbers' : 'NO'}
`;

  if (data.looksLikeDGA) {
    context += `
⚠️ DGA INDICATORS:
- Domain Generation Algorithm (DGA) patterns detected
- High entropy + length + numeric chars suggest automated generation
- Common in: Botnet C2, malware infrastructure, fast-flux DNS
`;
  }

  context += `
=== END DOMAIN ANALYSIS ===
`;

  return context.trim();
}

// ============================================================================
// URL ANALYSIS
// ============================================================================

interface URLAnalysis {
  raw: string;
  protocol: string;
  domain: DomainStructure;
  port: number | null;
  path: string;
  query: Record<string, string>;
  fragment: string | null;
  hasCredentials: boolean;
  suspiciousPatterns: string[];
  semanticContext: string;
}

const SUSPICIOUS_URL_PATTERNS = [
  { pattern: /\.exe$/i, description: 'Executable file download' },
  { pattern: /\.scr$/i, description: 'Screensaver (executable) download' },
  { pattern: /\.bat$/i, description: 'Batch file download' },
  { pattern: /\.ps1$/i, description: 'PowerShell script download' },
  { pattern: /\.vbs$/i, description: 'VBScript download' },
  { pattern: /\.js$/i, description: 'JavaScript file download' },
  { pattern: /data:/i, description: 'Data URI (can embed malicious content)' },
  { pattern: /javascript:/i, description: 'JavaScript URI scheme' },
  { pattern: /@/, description: 'Contains @ symbol (credential injection)' },
  { pattern: /\.(php|asp|aspx|jsp)\?/i, description: 'Dynamic script with parameters' },
  { pattern: /redirect|redir|goto|url=|link=/i, description: 'Potential open redirect' },
  { pattern: /login|signin|account|password|credential/i, description: 'Authentication-related path' },
  { pattern: /base64|eval|exec/i, description: 'Code execution patterns' },
  { pattern: /%00|%0a|%0d/i, description: 'Null byte or newline injection' },
  { pattern: /\.\.\/|\.\.\\/, description: 'Path traversal attempt' },
];

export function parseURL(url: string): URLAnalysis | null {
  try {
    const parsed = new URL(url);
    
    const domain = parseDomain(parsed.hostname);
    
    // Check for credentials in URL
    const hasCredentials = !!parsed.username || !!parsed.password;
    
    // Check for suspicious patterns
    const suspiciousPatterns: string[] = [];
    for (const { pattern, description } of SUSPICIOUS_URL_PATTERNS) {
      if (pattern.test(url)) {
        suspiciousPatterns.push(description);
      }
    }
    
    // Parse query parameters
    const query: Record<string, string> = {};
    parsed.searchParams.forEach((value, key) => {
      query[key] = value;
    });
    
    const result: URLAnalysis = {
      raw: url,
      protocol: parsed.protocol.replace(':', ''),
      domain,
      port: parsed.port ? parseInt(parsed.port) : null,
      path: parsed.pathname,
      query,
      fragment: parsed.hash ? parsed.hash.slice(1) : null,
      hasCredentials,
      suspiciousPatterns,
      semanticContext: ''
    };
    
    result.semanticContext = buildURLSemanticContext(result);
    
    return result;
  } catch {
    return null;
  }
}

function buildURLSemanticContext(url: URLAnalysis): string {
  let context = `
=== URL ANALYSIS ===

INDICATOR: ${url.raw}
TYPE: URL

COMPONENTS:
- Protocol: ${url.protocol}
- Domain: ${url.domain.normalized}
- Port: ${url.port || 'Default'}
- Path: ${url.path}
- Query params: ${Object.keys(url.query).length} parameters
- Fragment: ${url.fragment || 'None'}

PROTOCOL ANALYSIS:
- ${url.protocol === 'https' ? 'HTTPS (encrypted) - Note: Does NOT guarantee legitimacy' : 
    url.protocol === 'http' ? 'HTTP (unencrypted) - Data transmitted in plaintext' :
    `${url.protocol} - Non-standard protocol`}
`;

  if (url.hasCredentials) {
    context += `
⚠️ CREDENTIALS IN URL:
- URL contains embedded credentials
- This is a common phishing technique (e.g., https://google.com@evil.com)
- The part before @ is displayed but the actual destination is after @
`;
  }

  if (url.suspiciousPatterns.length > 0) {
    context += `
⚠️ SUSPICIOUS PATTERNS DETECTED:
${url.suspiciousPatterns.map(p => `- ${p}`).join('\n')}
`;
  }

  context += `
DOMAIN CONTEXT:
${url.domain.semanticContext}

=== END URL ANALYSIS ===
`;

  return context.trim();
}

// ============================================================================
// HASH ANALYSIS
// ============================================================================

interface HashAnalysis {
  raw: string;
  type: 'md5' | 'sha1' | 'sha256' | 'sha512' | 'unknown';
  normalized: string;
  isValid: boolean;
  semanticContext: string;
}

export function parseHash(hash: string): HashAnalysis {
  const normalized = hash.toLowerCase().trim();
  
  let type: HashAnalysis['type'] = 'unknown';
  let isValid = false;
  
  if (/^[a-f0-9]{32}$/.test(normalized)) {
    type = 'md5';
    isValid = true;
  } else if (/^[a-f0-9]{40}$/.test(normalized)) {
    type = 'sha1';
    isValid = true;
  } else if (/^[a-f0-9]{64}$/.test(normalized)) {
    type = 'sha256';
    isValid = true;
  } else if (/^[a-f0-9]{128}$/.test(normalized)) {
    type = 'sha512';
    isValid = true;
  }
  
  const semanticContext = `
=== HASH ANALYSIS ===

INDICATOR: ${hash}
TYPE: File Hash

HASH PROPERTIES:
- Algorithm: ${type.toUpperCase()}
- Length: ${normalized.length} characters
- Valid format: ${isValid ? 'YES' : 'NO'}
- Normalized: ${normalized}

HASH TYPE IMPLICATIONS:
${type === 'md5' ? '- MD5: Legacy algorithm, collision attacks possible. Still used by many threat intel feeds.' :
  type === 'sha1' ? '- SHA1: Deprecated for security. Collision attacks demonstrated. Still common in legacy systems.' :
  type === 'sha256' ? '- SHA256: Current standard. Widely supported. Best for threat intelligence.' :
  type === 'sha512' ? '- SHA512: Strong algorithm. Less common in threat intel feeds.' :
  '- Unknown hash format. May be truncated or custom encoding.'}

=== END HASH ANALYSIS ===
`.trim();

  return {
    raw: hash,
    type,
    normalized,
    isValid,
    semanticContext
  };
}

// ============================================================================
// EXPORTS
// ============================================================================

export type {
  IPClassification,
  ParsedIP,
  DomainStructure,
  URLAnalysis,
  HashAnalysis
};

export {
  IPV4_RANGES,
  HIGH_RISK_TLDS,
  TRUSTED_TLDS,
  NEUTRAL_TLDS,
  SUSPICIOUS_URL_PATTERNS,
  HOMOGLYPHS,
  BRAND_TARGETS,
  calculateEntropy,
  levenshteinDistance,
  normalizeHomoglyphs,
  detectHomoglyph
};
