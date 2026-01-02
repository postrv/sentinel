# Sentinel: AI-Augmented Security Investigation Platform

## Executive Summary

Sentinel is a security investigation platform designed for the AI age. It combines automated indicator analysis with LLM-powered reasoning and human-guided workflows. The system is built to be deployable cheaply on Cloudflare's edge infrastructure while providing enterprise-grade security investigation capabilities.

## Core Design Principles

### 1. Guided Automation, Not Full Automation
The platform doesn't try to replace security analysts—it amplifies them. Every automated finding includes:
- Confidence scoring with reasoning
- Suggested next steps
- Easy escalation paths
- Audit trails for compliance

### 2. LLM-Aware Data Handling
We explicitly handle tokenization issues that plague naive LLM security tools:
- IPs are pre-classified (RFC1918, CGNAT, multicast, bogon, etc.) before LLM analysis
- Domains are decomposed into meaningful parts (TLD reputation, entropy scores, age)
- Numeric data is converted to semantic descriptions
- Context windows are managed to prevent truncation of critical data

### 3. Defense in Depth Intelligence
Every finding links to preventative measures:
- DNS-level blocking recommendations
- Firewall rule generation
- Kubernetes NetworkPolicy templates
- EDR/SIEM correlation queries

### 4. Cost-Effective Edge Deployment
Built for Cloudflare's free/cheap tiers:
- Workers for compute (100k requests/day free)
- KV for caching (1GB free)
- D1 for persistence (5GB free)
- R2 for artifact storage (10GB free)
- Pages for frontend (unlimited)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           SENTINEL PLATFORM                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐            │
│  │   Frontend   │────▶│   Workers    │────▶│  LLM Engine  │            │
│  │  (CF Pages)  │     │   (CF Edge)  │     │  (Claude API)│            │
│  └──────────────┘     └──────┬───────┘     └──────────────┘            │
│                              │                                          │
│         ┌────────────────────┼────────────────────┐                     │
│         ▼                    ▼                    ▼                     │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐            │
│  │   D1 (SQL)   │     │   KV Cache   │     │  R2 Storage  │            │
│  │  - Findings  │     │  - API Cache │     │  - Artifacts │            │
│  │  - Audit Log │     │  - Sessions  │     │  - Reports   │            │
│  │  - Policies  │     │  - Rate Lim  │     │  - Evidence  │            │
│  └──────────────┘     └──────────────┘     └──────────────┘            │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                        EXTERNAL INTEGRATIONS                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐          │
│  │VirusTo- │ │ AbuseIP │ │ Shodan  │ │GreyNoise│ │URLScan  │          │
│  │  tal    │ │   DB    │ │         │ │         │ │  .io    │          │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘          │
│                                                                          │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐          │
│  │  WHOIS  │ │ BGPView │ │   CT    │ │  DNS    │ │AlienVlt │          │
│  │         │ │   ASN   │ │  Logs   │ │  Over   │ │   OTX   │          │
│  │         │ │         │ │         │ │  HTTPS  │ │         │          │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘          │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Module Breakdown

### 1. Indicator Analysis Engine (`/api/analyze`)

#### IP Analysis
```typescript
interface IPAnalysis {
  // Pre-computed classifications (helps LLM tokenization)
  classification: {
    type: 'public' | 'private' | 'reserved' | 'multicast' | 'loopback' | 'cgnat' | 'documentation';
    rfc: string;  // e.g., "RFC1918", "RFC6598"
    humanDescription: string;  // "Private network (home/corporate LAN)"
  };
  
  // Reputation data
  reputation: {
    abuseipdb: { score: number; reports: number; lastSeen: Date };
    virustotal: { malicious: number; suspicious: number; clean: number };
    greynoise: { classification: string; noise: boolean; riot: boolean };
    shodan: { ports: number[]; vulns: string[]; tags: string[] };
  };
  
  // Geolocation & Network
  geo: { country: string; city: string; asn: number; org: string; isp: string };
  
  // Reverse DNS
  rdns: string[];
  
  // Historical context
  history: { firstSeen: Date; lastSeen: Date; changingBehavior: boolean };
}
```

#### Domain Analysis
```typescript
interface DomainAnalysis {
  // Structural analysis
  structure: {
    tld: string;
    tldReputation: 'trusted' | 'neutral' | 'suspicious' | 'high-risk';
    registrar: string;
    ageInDays: number;
    entropy: number;  // Shannon entropy for DGA detection
    length: number;
    hasNumbers: boolean;
    hasDashes: boolean;
    subdomainDepth: number;
  };
  
  // WHOIS
  whois: {
    registrant: string;
    created: Date;
    expires: Date;
    privacyProtected: boolean;
    nameservers: string[];
  };
  
  // DNS records
  dns: {
    a: string[];
    aaaa: string[];
    mx: string[];
    txt: string[];
    ns: string[];
    cname: string;
  };
  
  // Certificate transparency
  certificates: {
    issuer: string;
    validFrom: Date;
    validTo: Date;
    altNames: string[];
  }[];
  
  // Reputation
  reputation: {
    virustotal: { malicious: number; suspicious: number };
    urlscan: { verdicts: string[]; screenshots: string[] };
    googleSafeBrowsing: { threat: boolean; type: string };
  };
}
```

### 2. LLM Analysis Layer

The key innovation here is **semantic pre-processing**. Instead of sending raw IPs/domains to the LLM, we:

```typescript
// BAD: Raw IP gets tokenized poorly
const badPrompt = "Analyze 192.168.1.1";

// GOOD: Semantic context helps the LLM
const goodPrompt = `
Analyze this indicator:

TYPE: IPv4 Address
RAW VALUE: 192.168.1.1
CLASSIFICATION: Private (RFC1918 - 192.168.0.0/16)
SEMANTIC MEANING: Local network address, typically home router or internal corporate device
OCTET BREAKDOWN: Network=192.168, Host=1.1
DECIMAL REPRESENTATION: 3232235777
IS INTERNET ROUTABLE: No

CONTEXT: Found in DNS query logs from endpoint DESKTOP-ABC123

Based on this classification, this IP cannot be malicious external infrastructure.
However, if seen in external traffic, it indicates NAT traversal issues or misconfiguration.
`;
```

### 3. Kubernetes Security Module

```typescript
interface K8sSecurityAnalysis {
  // Cluster-level
  cluster: {
    version: string;
    cveExposure: string[];
    admissionControllers: string[];
    podSecurityStandards: 'privileged' | 'baseline' | 'restricted';
  };
  
  // Workload analysis
  workloads: {
    name: string;
    namespace: string;
    issues: {
      severity: 'critical' | 'high' | 'medium' | 'low';
      category: 'privileges' | 'network' | 'secrets' | 'images' | 'resources';
      description: string;
      remediation: string;
    }[];
  }[];
  
  // Network policies
  networkPolicies: {
    coverage: number;  // % of pods with policies
    gaps: string[];    // Namespaces/pods without policies
    recommendations: string[];
  };
  
  // RBAC analysis
  rbac: {
    overPrivilegedRoles: string[];
    clusterAdminBindings: string[];
    serviceAccountRisks: string[];
  };
}
```

### 4. Human-in-the-Loop Workflows

```typescript
interface InvestigationWorkflow {
  id: string;
  indicator: string;
  status: 'pending' | 'investigating' | 'escalated' | 'resolved' | 'false_positive';
  
  // AI-generated guidance
  guidance: {
    summary: string;
    riskScore: number;  // 0-100
    confidence: number; // 0-100
    suggestedActions: Action[];
    questionsForAnalyst: string[];
  };
  
  // Human decisions
  decisions: {
    timestamp: Date;
    analyst: string;
    action: string;
    rationale: string;
  }[];
  
  // Preventative outputs
  mitigations: {
    firewallRules: string[];
    dnsBlocks: string[];
    k8sNetworkPolicies: string[];
    siemQueries: string[];
  };
}
```

## API Endpoints

### Core Analysis
- `POST /api/analyze/ip` - Analyze an IP address
- `POST /api/analyze/domain` - Analyze a domain
- `POST /api/analyze/url` - Analyze a URL (includes domain + path analysis)
- `POST /api/analyze/hash` - Analyze a file hash
- `POST /api/analyze/bulk` - Bulk analysis of multiple indicators

### Investigation Workflows
- `POST /api/investigate/start` - Start a new investigation
- `GET /api/investigate/:id` - Get investigation status
- `POST /api/investigate/:id/decision` - Record analyst decision
- `POST /api/investigate/:id/escalate` - Escalate to senior analyst
- `GET /api/investigate/:id/report` - Generate investigation report

### Kubernetes Security
- `POST /api/k8s/analyze-manifest` - Analyze K8s YAML for issues
- `POST /api/k8s/generate-netpol` - Generate NetworkPolicy from requirements
- `POST /api/k8s/rbac-audit` - Audit RBAC configuration
- `POST /api/k8s/image-scan` - Trigger image vulnerability scan

### Mitigation Generation
- `POST /api/mitigate/firewall` - Generate firewall rules
- `POST /api/mitigate/dns` - Generate DNS blocklist entries
- `POST /api/mitigate/siem` - Generate SIEM detection queries

## Data Flow Example

```
User submits suspicious domain: "xn--80ak6aa92e.com"

1. STRUCTURAL ANALYSIS
   - Detected: Punycode (IDN) domain
   - Decoded: "apple.com" lookalike (homoglyph attack)
   - Entropy: 2.8 (low, not DGA)
   - Age: 3 days
   - TLD: .com (trusted, but abused)

2. EXTERNAL ENRICHMENT (parallel, cached)
   - VirusTotal: 12/94 malicious
   - URLScan: Phishing kit detected
   - WHOIS: Privacy protected, NameCheap
   - CT Logs: Single cert, Let's Encrypt

3. LLM ANALYSIS
   Input (semantic pre-processing):
   - Domain type: Punycode/IDN (internationalized)
   - Visual similarity: High similarity to "apple.com"
   - Attack pattern: Homoglyph/lookalike phishing
   - Age risk: Very new (3 days) - high risk
   - Certificate: Free DV cert (common for phishing)
   
   Output:
   - Risk score: 92/100
   - Confidence: 87/100
   - Classification: Likely phishing infrastructure
   - Questions for analyst:
     1. Has any user actually visited this domain?
     2. Any credential submissions detected?
     3. Is this targeting specific users or broad?

4. MITIGATION GENERATION
   - DNS block: xn--80ak6aa92e.com
   - Firewall: Block resolved IPs
   - SIEM query: dns.query.name:"xn--80ak6aa92e.com"
   - Email filter: Block emails containing domain

5. HUMAN REVIEW
   Analyst reviews, confirms phishing, adds context:
   "Targeted at finance team via LinkedIn messages"
   
6. CASE CLOSURE
   - Block deployed
   - IOCs shared to threat intel
   - Report generated for compliance
```

## Security Considerations

### API Keys Management
- All external API keys stored in Cloudflare Secrets
- Keys never exposed to frontend
- Rate limiting per-key to prevent abuse

### Authentication
- JWT-based auth with short expiry
- Role-based access (analyst, senior, admin)
- Audit logging of all actions

### Data Handling
- No PII stored beyond necessary
- Automatic data expiry (configurable)
- Encryption at rest (D1/R2)

## Deployment

### Cloudflare Resources Required
```toml
# wrangler.toml
name = "sentinel"
main = "src/worker.ts"
compatibility_date = "2024-01-01"

[[d1_databases]]
binding = "DB"
database_name = "sentinel"
database_id = "xxx"

[[kv_namespaces]]
binding = "CACHE"
id = "xxx"

[[r2_buckets]]
binding = "ARTIFACTS"
bucket_name = "sentinel-artifacts"

[vars]
ENVIRONMENT = "production"

[secrets]
# Set via wrangler secret put
# VT_API_KEY, ABUSEIPDB_KEY, SHODAN_KEY, etc.
```

### Cost Estimate (Monthly)
- Workers: Free tier (100k req/day)
- D1: Free tier (5GB, 5M rows)
- KV: Free tier (1GB, 100k reads/day)
- R2: Free tier (10GB)
- **Total: $0/month for moderate usage**

For higher usage:
- Workers Paid: $5/month (10M req)
- D1 Paid: $5/month (25GB)
- **Total: ~$10/month for enterprise usage**

## Future Enhancements

1. **MCP Integration**: Expose as MCP server for direct Claude integration
2. **SOAR Integration**: Webhook triggers for Tines/Phantom/XSOAR
3. **Threat Intel Sharing**: STIX/TAXII export
4. **ML Models**: Custom classifier for organization-specific threats
5. **Browser Extension**: Quick lookup from any page
