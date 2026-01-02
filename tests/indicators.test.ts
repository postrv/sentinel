import { describe, it, expect } from 'vitest';
import {
  parseIPv4,
  parseDomain,
  parseURL,
  parseHash,
  calculateEntropy,
  levenshteinDistance,
  normalizeHomoglyphs,
  detectHomoglyph,
  IPV4_RANGES,
  HIGH_RISK_TLDS,
  TRUSTED_TLDS,
} from '../src/lib/indicators';

// =============================================================================
// IPv4 PARSING TESTS
// =============================================================================

describe('parseIPv4', () => {
  describe('valid IPv4 addresses', () => {
    it('should parse a valid public IP address', () => {
      const result = parseIPv4('8.8.8.8');
      expect(result).not.toBeNull();
      expect(result!.raw).toBe('8.8.8.8');
      expect(result!.version).toBe(4);
      expect(result!.octets).toEqual([8, 8, 8, 8]);
      expect(result!.classification.type).toBe('public');
      expect(result!.classification.isInternetRoutable).toBe(true);
    });

    it('should parse a private 10.x.x.x address (RFC1918)', () => {
      const result = parseIPv4('10.0.0.1');
      expect(result).not.toBeNull();
      expect(result!.classification.type).toBe('private');
      expect(result!.classification.rfc).toBe('RFC1918');
      expect(result!.classification.isInternetRoutable).toBe(false);
    });

    it('should parse a private 172.16.x.x address (RFC1918)', () => {
      const result = parseIPv4('172.16.0.1');
      expect(result).not.toBeNull();
      expect(result!.classification.type).toBe('private');
      expect(result!.classification.rfc).toBe('RFC1918');
    });

    it('should parse a private 192.168.x.x address (RFC1918)', () => {
      const result = parseIPv4('192.168.1.1');
      expect(result).not.toBeNull();
      expect(result!.classification.type).toBe('private');
      expect(result!.classification.rfc).toBe('RFC1918');
      expect(result!.classification.cidr).toBe('192.168.0.0/16');
    });

    it('should parse a loopback address', () => {
      const result = parseIPv4('127.0.0.1');
      expect(result).not.toBeNull();
      expect(result!.classification.type).toBe('loopback');
      expect(result!.classification.rfc).toBe('RFC1122');
    });

    it('should parse a link-local address', () => {
      const result = parseIPv4('169.254.1.1');
      expect(result).not.toBeNull();
      expect(result!.classification.type).toBe('link-local');
      expect(result!.classification.rfc).toBe('RFC3927');
    });

    it('should parse a CGNAT address (RFC6598)', () => {
      const result = parseIPv4('100.64.0.1');
      expect(result).not.toBeNull();
      expect(result!.classification.type).toBe('cgnat');
      expect(result!.classification.rfc).toBe('RFC6598');
    });

    it('should parse a multicast address', () => {
      const result = parseIPv4('224.0.0.1');
      expect(result).not.toBeNull();
      expect(result!.classification.type).toBe('multicast');
    });

    it('should parse a documentation address (TEST-NET-1)', () => {
      const result = parseIPv4('192.0.2.1');
      expect(result).not.toBeNull();
      expect(result!.classification.type).toBe('documentation');
      expect(result!.classification.rfc).toBe('RFC5737');
    });

    it('should parse a documentation address (TEST-NET-2)', () => {
      const result = parseIPv4('198.51.100.1');
      expect(result).not.toBeNull();
      expect(result!.classification.type).toBe('documentation');
    });

    it('should parse a documentation address (TEST-NET-3)', () => {
      const result = parseIPv4('203.0.113.1');
      expect(result).not.toBeNull();
      expect(result!.classification.type).toBe('documentation');
    });

    it('should parse broadcast address', () => {
      const result = parseIPv4('255.255.255.255');
      expect(result).not.toBeNull();
      expect(result!.classification.type).toBe('broadcast');
    });

    it('should correctly calculate decimal representation', () => {
      const result = parseIPv4('192.168.1.1');
      expect(result).not.toBeNull();
      // 192*2^24 + 168*2^16 + 1*2^8 + 1 = 3232235777
      expect(result!.decimal).toBe(BigInt(3232235777));
    });

    it('should correctly calculate binary representation', () => {
      const result = parseIPv4('192.168.1.1');
      expect(result).not.toBeNull();
      expect(result!.binary).toBe('11000000101010000000000100000001');
    });

    it('should generate semantic context', () => {
      const result = parseIPv4('8.8.8.8');
      expect(result).not.toBeNull();
      expect(result!.semanticContext).toContain('IP ADDRESS ANALYSIS');
      expect(result!.semanticContext).toContain('8.8.8.8');
      expect(result!.semanticContext).toContain('IPv4 Address');
    });
  });

  describe('invalid IPv4 addresses', () => {
    it('should return null for empty string', () => {
      expect(parseIPv4('')).toBeNull();
    });

    it('should return null for non-IP string', () => {
      expect(parseIPv4('hello')).toBeNull();
    });

    it('should return null for IPv6 address', () => {
      expect(parseIPv4('::1')).toBeNull();
    });

    it('should return null for IP with too few octets', () => {
      expect(parseIPv4('192.168.1')).toBeNull();
    });

    it('should return null for IP with too many octets', () => {
      expect(parseIPv4('192.168.1.1.1')).toBeNull();
    });

    it('should return null for IP with octet > 255', () => {
      expect(parseIPv4('256.1.1.1')).toBeNull();
    });

    it('should return null for IP with negative octet', () => {
      expect(parseIPv4('-1.1.1.1')).toBeNull();
    });

    it('should return null for IP with non-numeric octet', () => {
      expect(parseIPv4('abc.1.1.1')).toBeNull();
    });
  });

  describe('edge cases', () => {
    it('should handle minimum IP 0.0.0.0', () => {
      const result = parseIPv4('0.0.0.0');
      expect(result).not.toBeNull();
      expect(result!.classification.type).toBe('reserved');
    });

    it('should handle boundary between private and public ranges', () => {
      // Just outside 10.0.0.0/8
      const publicIP = parseIPv4('11.0.0.1');
      expect(publicIP!.classification.type).toBe('public');

      // Just inside 10.0.0.0/8
      const privateIP = parseIPv4('10.255.255.255');
      expect(privateIP!.classification.type).toBe('private');
    });
  });
});

// =============================================================================
// DOMAIN PARSING TESTS
// =============================================================================

describe('parseDomain', () => {
  describe('basic domain parsing', () => {
    it('should parse a simple domain', () => {
      const result = parseDomain('example.com');
      expect(result.raw).toBe('example.com');
      expect(result.normalized).toBe('example.com');
      expect(result.tld).toBe('com');
      expect(result.sld).toBe('example');
      expect(result.subdomain).toBeNull();
      expect(result.depth).toBe(2);
    });

    it('should parse a domain with subdomain', () => {
      const result = parseDomain('www.example.com');
      expect(result.subdomain).toBe('www');
      expect(result.sld).toBe('example');
      expect(result.tld).toBe('com');
      expect(result.depth).toBe(3);
    });

    it('should parse a domain with multiple subdomains', () => {
      const result = parseDomain('mail.corp.example.com');
      expect(result.subdomain).toBe('mail.corp');
      expect(result.depth).toBe(4);
    });

    it('should normalize to lowercase', () => {
      const result = parseDomain('EXAMPLE.COM');
      expect(result.normalized).toBe('example.com');
    });

    it('should trim whitespace', () => {
      const result = parseDomain('  example.com  ');
      expect(result.normalized).toBe('example.com');
    });
  });

  describe('punycode detection', () => {
    it('should detect punycode domains', () => {
      const result = parseDomain('xn--n3h.com');
      expect(result.isPunycode).toBe(true);
    });

    it('should not flag regular domains as punycode', () => {
      const result = parseDomain('example.com');
      expect(result.isPunycode).toBe(false);
    });
  });

  describe('entropy calculation', () => {
    it('should calculate low entropy for word-like domains', () => {
      const result = parseDomain('google.com');
      expect(result.entropy).toBeLessThan(3.0);
    });

    it('should calculate high entropy for random-looking domains', () => {
      const result = parseDomain('x7k9m2p4q8w3.com');
      expect(result.entropy).toBeGreaterThan(3.0);
    });
  });

  describe('DGA detection', () => {
    it('should flag high-entropy long domains with numbers as DGA-like', () => {
      const result = parseDomain('a1b2c3d4e5f6g7h8i9j0k.com');
      expect(result.looksLikeDGA).toBe(true);
    });

    it('should not flag short word-like domains as DGA', () => {
      const result = parseDomain('google.com');
      expect(result.looksLikeDGA).toBe(false);
    });
  });

  describe('pattern detection', () => {
    it('should detect numbers in domain', () => {
      const result = parseDomain('example123.com');
      expect(result.hasNumbers).toBe(true);
    });

    it('should detect dashes in domain', () => {
      const result = parseDomain('my-example.com');
      expect(result.hasDashes).toBe(true);
    });

    it('should detect underscores in domain', () => {
      const result = parseDomain('my_example.com');
      expect(result.hasUnderscores).toBe(true);
    });
  });

  describe('homoglyph detection', () => {
    it('should detect homoglyph targeting google', () => {
      const result = parseDomain('g00gle.com');
      expect(result.homoglyphTarget).toBe('google');
    });

    it('should detect homoglyph targeting paypal', () => {
      const result = parseDomain('paypa1.com');
      expect(result.homoglyphTarget).toBe('paypal');
    });

    it('should not flag legitimate domains', () => {
      const result = parseDomain('mycompany.com');
      expect(result.homoglyphTarget).toBeNull();
    });
  });

  describe('semantic context generation', () => {
    it('should generate semantic context', () => {
      const result = parseDomain('example.com');
      expect(result.semanticContext).toContain('DOMAIN ANALYSIS');
      expect(result.semanticContext).toContain('example.com');
      expect(result.semanticContext).toContain('TLD');
    });

    it('should include DGA warning for suspicious domains', () => {
      const result = parseDomain('a1b2c3d4e5f6g7h8i9j0k.com');
      expect(result.semanticContext).toContain('DGA');
    });
  });
});

// =============================================================================
// URL PARSING TESTS
// =============================================================================

describe('parseURL', () => {
  describe('valid URLs', () => {
    it('should parse a simple HTTPS URL', () => {
      const result = parseURL('https://example.com');
      expect(result).not.toBeNull();
      expect(result!.protocol).toBe('https');
      expect(result!.domain.normalized).toBe('example.com');
      expect(result!.path).toBe('/');
    });

    it('should parse URL with path', () => {
      const result = parseURL('https://example.com/path/to/page');
      expect(result).not.toBeNull();
      expect(result!.path).toBe('/path/to/page');
    });

    it('should parse URL with query parameters', () => {
      const result = parseURL('https://example.com/search?q=test&page=1');
      expect(result).not.toBeNull();
      expect(result!.query.q).toBe('test');
      expect(result!.query.page).toBe('1');
    });

    it('should parse URL with port', () => {
      const result = parseURL('https://example.com:8443/api');
      expect(result).not.toBeNull();
      expect(result!.port).toBe(8443);
    });

    it('should parse URL with fragment', () => {
      const result = parseURL('https://example.com/page#section');
      expect(result).not.toBeNull();
      expect(result!.fragment).toBe('section');
    });

    it('should handle HTTP URLs', () => {
      const result = parseURL('http://example.com');
      expect(result).not.toBeNull();
      expect(result!.protocol).toBe('http');
    });
  });

  describe('suspicious pattern detection', () => {
    it('should detect .exe file downloads', () => {
      const result = parseURL('https://example.com/download/file.exe');
      expect(result).not.toBeNull();
      expect(result!.suspiciousPatterns).toContain('Executable file download');
    });

    it('should detect .ps1 PowerShell script downloads', () => {
      const result = parseURL('https://example.com/script.ps1');
      expect(result).not.toBeNull();
      expect(result!.suspiciousPatterns).toContain('PowerShell script download');
    });

    it('should detect credential injection (@ in URL)', () => {
      const result = parseURL('https://google.com@evil.com/phishing');
      expect(result).not.toBeNull();
      expect(result!.hasCredentials).toBe(true);
    });

    it('should detect path traversal attempts', () => {
      const result = parseURL('https://example.com/../../etc/passwd');
      expect(result).not.toBeNull();
      expect(result!.suspiciousPatterns).toContain('Path traversal attempt');
    });

    it('should detect redirect patterns', () => {
      const result = parseURL('https://example.com/redirect?url=evil.com');
      expect(result).not.toBeNull();
      expect(result!.suspiciousPatterns).toContain('Potential open redirect');
    });

    it('should detect login-related paths', () => {
      const result = parseURL('https://example.com/login/account');
      expect(result).not.toBeNull();
      expect(result!.suspiciousPatterns).toContain('Authentication-related path');
    });
  });

  describe('invalid URLs', () => {
    it('should return null for invalid URL', () => {
      expect(parseURL('not-a-url')).toBeNull();
    });

    it('should return null for empty string', () => {
      expect(parseURL('')).toBeNull();
    });
  });

  describe('semantic context', () => {
    it('should generate semantic context for URLs', () => {
      const result = parseURL('https://example.com/page');
      expect(result).not.toBeNull();
      expect(result!.semanticContext).toContain('URL ANALYSIS');
      expect(result!.semanticContext).toContain('HTTPS');
    });

    it('should warn about credentials in URL', () => {
      const result = parseURL('https://user@example.com');
      expect(result).not.toBeNull();
      expect(result!.semanticContext).toContain('CREDENTIALS');
    });
  });
});

// =============================================================================
// HASH PARSING TESTS
// =============================================================================

describe('parseHash', () => {
  describe('MD5 hashes', () => {
    it('should detect valid MD5 hash', () => {
      const result = parseHash('d41d8cd98f00b204e9800998ecf8427e');
      expect(result.type).toBe('md5');
      expect(result.isValid).toBe(true);
      expect(result.normalized).toBe('d41d8cd98f00b204e9800998ecf8427e');
    });

    it('should normalize uppercase MD5', () => {
      const result = parseHash('D41D8CD98F00B204E9800998ECF8427E');
      expect(result.type).toBe('md5');
      expect(result.normalized).toBe('d41d8cd98f00b204e9800998ecf8427e');
    });
  });

  describe('SHA1 hashes', () => {
    it('should detect valid SHA1 hash', () => {
      const result = parseHash('da39a3ee5e6b4b0d3255bfef95601890afd80709');
      expect(result.type).toBe('sha1');
      expect(result.isValid).toBe(true);
    });
  });

  describe('SHA256 hashes', () => {
    it('should detect valid SHA256 hash', () => {
      const result = parseHash('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      expect(result.type).toBe('sha256');
      expect(result.isValid).toBe(true);
    });
  });

  describe('SHA512 hashes', () => {
    it('should detect valid SHA512 hash', () => {
      const hash = 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e';
      const result = parseHash(hash);
      expect(result.type).toBe('sha512');
      expect(result.isValid).toBe(true);
    });
  });

  describe('invalid hashes', () => {
    it('should mark non-hex string as unknown', () => {
      const result = parseHash('not-a-hash');
      expect(result.type).toBe('unknown');
      expect(result.isValid).toBe(false);
    });

    it('should mark wrong-length hex as unknown', () => {
      const result = parseHash('abc123');
      expect(result.type).toBe('unknown');
      expect(result.isValid).toBe(false);
    });
  });

  describe('semantic context', () => {
    it('should generate semantic context with algorithm info', () => {
      const result = parseHash('d41d8cd98f00b204e9800998ecf8427e');
      expect(result.semanticContext).toContain('HASH ANALYSIS');
      expect(result.semanticContext).toContain('MD5');
    });
  });
});

// =============================================================================
// UTILITY FUNCTION TESTS
// =============================================================================

describe('calculateEntropy', () => {
  it('should return 0 for single character string', () => {
    const entropy = calculateEntropy('aaaa');
    expect(entropy).toBe(0);
  });

  it('should calculate low entropy for repeated patterns', () => {
    const entropy = calculateEntropy('abab');
    expect(entropy).toBeLessThan(2);
  });

  it('should calculate high entropy for random strings', () => {
    const entropy = calculateEntropy('a1b2c3d4');
    expect(entropy).toBeGreaterThan(2.5);
  });
});

describe('levenshteinDistance', () => {
  it('should return 0 for identical strings', () => {
    expect(levenshteinDistance('hello', 'hello')).toBe(0);
  });

  it('should return string length for empty comparison', () => {
    expect(levenshteinDistance('hello', '')).toBe(5);
    expect(levenshteinDistance('', 'hello')).toBe(5);
  });

  it('should calculate correct distance for one substitution', () => {
    expect(levenshteinDistance('hello', 'hallo')).toBe(1);
  });

  it('should calculate correct distance for one insertion', () => {
    expect(levenshteinDistance('hello', 'helloo')).toBe(1);
  });

  it('should calculate correct distance for one deletion', () => {
    expect(levenshteinDistance('hello', 'helo')).toBe(1);
  });

  it('should calculate correct distance for multiple edits', () => {
    expect(levenshteinDistance('kitten', 'sitting')).toBe(3);
  });
});

describe('normalizeHomoglyphs', () => {
  it('should normalize Cyrillic a to Latin a', () => {
    expect(normalizeHomoglyphs('pаypal')).toBe('paypal');
  });

  it('should normalize 0 to o', () => {
    expect(normalizeHomoglyphs('g00gle')).toBe('google');
  });

  it('should normalize 1 to l/i', () => {
    expect(normalizeHomoglyphs('paypa1')).toBe('paypal');
  });

  it('should normalize rn to m', () => {
    expect(normalizeHomoglyphs('arnazon')).toBe('amazon');
  });

  it('should handle multiple substitutions', () => {
    expect(normalizeHomoglyphs('g00g1е')).toBe('google');
  });
});

describe('detectHomoglyph', () => {
  it('should detect google homoglyph', () => {
    expect(detectHomoglyph('g00gle.com')).toBe('google');
  });

  it('should detect paypal homoglyph', () => {
    expect(detectHomoglyph('paypa1.com')).toBe('paypal');
  });

  it('should detect amazon homoglyph (rn -> m)', () => {
    expect(detectHomoglyph('arnazon.com')).toBe('amazon');
  });

  it('should detect microsoft homoglyph', () => {
    expect(detectHomoglyph('micr0soft.com')).toBe('microsoft');
  });

  it('should return null for non-impersonating domain', () => {
    expect(detectHomoglyph('mycompany.com')).toBeNull();
  });

  it('should return null for legitimate brand domain', () => {
    // The actual google.com should not trigger detection
    expect(detectHomoglyph('google.com')).toBeNull();
  });
});

// =============================================================================
// TLD SETS TESTS
// =============================================================================

describe('TLD classifications', () => {
  it('HIGH_RISK_TLDS should contain known abuse TLDs', () => {
    expect(HIGH_RISK_TLDS.has('tk')).toBe(true);
    expect(HIGH_RISK_TLDS.has('xyz')).toBe(true);
    expect(HIGH_RISK_TLDS.has('zip')).toBe(true);
  });

  it('TRUSTED_TLDS should contain verified TLDs', () => {
    expect(TRUSTED_TLDS.has('gov')).toBe(true);
    expect(TRUSTED_TLDS.has('edu')).toBe(true);
    expect(TRUSTED_TLDS.has('bank')).toBe(true);
  });
});

// =============================================================================
// IPV4_RANGES TESTS
// =============================================================================

describe('IPV4_RANGES', () => {
  it('should have all major private ranges', () => {
    const cidrs = IPV4_RANGES.map(r => r.cidr);
    expect(cidrs).toContain('10.0.0.0/8');
    expect(cidrs).toContain('172.16.0.0/12');
    expect(cidrs).toContain('192.168.0.0/16');
  });

  it('should have loopback range', () => {
    const loopback = IPV4_RANGES.find(r => r.classification.type === 'loopback');
    expect(loopback).toBeDefined();
    expect(loopback!.cidr).toBe('127.0.0.0/8');
  });

  it('should have non-overlapping ranges', () => {
    for (let i = 0; i < IPV4_RANGES.length; i++) {
      for (let j = i + 1; j < IPV4_RANGES.length; j++) {
        const a = IPV4_RANGES[i];
        const b = IPV4_RANGES[j];
        // Check for no overlap (one must end before the other starts)
        const noOverlap = a.end < b.start || b.end < a.start;
        expect(noOverlap).toBe(true);
      }
    }
  });
});
