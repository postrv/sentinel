# Sentinel

**AI-Augmented Security Investigation Platform**

Sentinel is a comprehensive threat intelligence and security investigation tool that combines automated enrichment from multiple threat feeds, LLM-powered analysis, and human-in-the-loop workflows. Built for security operations teams who need to rapidly triage and respond to potential threats.

## Key Features

- **Multi-source threat intelligence**: Aggregates data from VirusTotal, AbuseIPDB, Shodan, GreyNoise, URLScan, and more
- **LLM-powered analysis**: Uses Claude to reason about indicators with semantic preprocessing for accurate IP/domain understanding
- **Kubernetes security analysis**: Scans manifests for security misconfigurations with automated remediation suggestions
- **Automated mitigation generation**: Produces firewall rules, DNS blocks, SIEM queries, and K8s NetworkPolicies
- **MCP integration**: Native Model Context Protocol server for direct Claude Desktop integration
- **Edge deployment**: Runs on Cloudflare Workers for global low-latency access at minimal cost ($0-10/month)

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SENTINEL PLATFORM                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   Web UI    │    │  MCP Server │    │   Browser   │    │    API      │  │
│  │  (React)    │    │  (Claude)   │    │  Extension  │    │  Consumers  │  │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘  │
│         │                  │                  │                  │         │
│         └──────────────────┴──────────────────┴──────────────────┘         │
│                                    │                                        │
│                    ┌───────────────┴───────────────┐                       │
│                    │    Cloudflare Worker (Edge)    │                       │
│                    │                                │                       │
│                    │  ┌──────────────────────────┐ │                       │
│                    │  │  Indicator Preprocessor  │ │                       │
│                    │  │  • Type detection        │ │                       │
│                    │  │  • RFC classification    │ │                       │
│                    │  │  • Semantic context      │ │                       │
│                    │  └────────────┬─────────────┘ │                       │
│                    │               │               │                       │
│                    │  ┌────────────┴─────────────┐ │                       │
│                    │  │   Enrichment Orchestrator │ │                       │
│                    │  │  • Parallel API calls    │ │                       │
│                    │  │  • Response caching (KV) │ │                       │
│                    │  │  • Rate limiting         │ │                       │
│                    │  └────────────┬─────────────┘ │                       │
│                    │               │               │                       │
│                    │  ┌────────────┴─────────────┐ │                       │
│                    │  │     LLM Analysis Layer   │ │                       │
│                    │  │  • Claude API            │ │                       │
│                    │  │  • Structured output     │ │                       │
│                    │  │  • Confidence scoring    │ │                       │
│                    │  └──────────────────────────┘ │                       │
│                    └───────────────────────────────┘                       │
│                                    │                                        │
│         ┌──────────────────────────┼──────────────────────────┐            │
│         │                          │                          │            │
│    ┌────┴────┐              ┌──────┴──────┐            ┌──────┴──────┐     │
│    │   D1    │              │     KV      │            │     R2      │     │
│    │ SQLite  │              │   Cache     │            │  Artifacts  │     │
│    └─────────┘              └─────────────┘            └─────────────┘     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
          ┌──────────────────────────┼──────────────────────────┐
          │                          │                          │
     ┌────┴────┐              ┌──────┴──────┐            ┌──────┴──────┐
     │VirusTotal│              │  AbuseIPDB  │            │   Shodan    │
     └─────────┘              └─────────────┘            └─────────────┘
          │                          │                          │
     ┌────┴────┐              ┌──────┴──────┐            ┌──────┴──────┐
     │GreyNoise │              │  URLScan    │            │   WHOIS     │
     └─────────┘              └─────────────┘            └─────────────┘
```

## Quick Start

### Prerequisites

- Node.js 18+
- Cloudflare account (free tier works)
- API keys for threat intelligence services (optional, but recommended)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/sentinel
cd sentinel

# Install dependencies
npm install

# Install Wrangler CLI globally
npm install -g wrangler

# Authenticate with Cloudflare
wrangler login
```

### Configure Cloudflare Resources

```bash
# Create D1 database
wrangler d1 create sentinel
# Copy the database_id to wrangler.toml

# Create KV namespace for caching
wrangler kv:namespace create CACHE
# Copy the id to wrangler.toml

# Create R2 bucket for artifacts
wrangler r2 bucket create sentinel-artifacts

# Run database migrations
npm run db:migrate
```

### Configure API Keys

```bash
# Set up threat intelligence API keys (run each and paste your key)
wrangler secret put VT_API_KEY
wrangler secret put ABUSEIPDB_KEY
wrangler secret put SHODAN_KEY
wrangler secret put GREYNOISE_KEY
wrangler secret put URLSCAN_KEY
wrangler secret put ANTHROPIC_API_KEY
```

### Deploy

```bash
# Deploy to Cloudflare Workers
npm run deploy

# Your API is now live at https://sentinel.<your-subdomain>.workers.dev
```

## Usage

### Web Interface

Access the dashboard at your deployed URL. Enter any indicator to analyze:

- **IP addresses**: `185.220.101.1`, `192.168.1.1`
- **Domains**: `suspicious-domain.xyz`, `xn--80ak6aa92e.com`
- **URLs**: `https://malware-site.com/payload.exe`
- **Hashes**: `44d88612fea8a8f36de82e1278abb02f` (MD5/SHA1/SHA256)

### API Endpoints

```bash
# Analyze an indicator
curl -X POST https://sentinel.yoursite.workers.dev/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"indicator": "185.220.101.1"}'

# Analyze Kubernetes manifest
curl -X POST https://sentinel.yoursite.workers.dev/api/k8s/analyze \
  -H "Content-Type: application/json" \
  -d '{"manifest": "<your-k8s-yaml>"}'
```

### MCP Server (Claude Desktop Integration)

The MCP server allows Claude to directly query threat intelligence and generate security artifacts.

```bash
# Install globally
npm link

# Add to Claude Desktop config (~/.config/claude/config.json on Linux)
{
  "mcpServers": {
    "sentinel": {
      "command": "sentinel-mcp",
      "env": {
        "VT_API_KEY": "your-virustotal-key",
        "ABUSEIPDB_KEY": "your-abuseipdb-key",
        "SHODAN_KEY": "your-shodan-key",
        "GREYNOISE_KEY": "your-greynoise-key"
      }
    }
  }
}
```

Now Claude can use tools like:
- `analyze_indicator` - Full threat intelligence lookup
- `analyze_k8s_manifest` - Security scan of Kubernetes configs
- `generate_firewall_rules` - Multi-platform firewall rules
- `generate_siem_query` - Threat hunting queries for Splunk/Elastic/Sentinel
- `generate_network_policy` - Kubernetes NetworkPolicy generation

## LLM-Aware Design

Sentinel is designed specifically to work well with LLMs, addressing common issues with AI-powered security tools:

### Tokenization Handling

IP addresses like `192.168.1.1` get tokenized unpredictably by LLMs. Sentinel pre-computes semantic context:

```javascript
// Instead of sending raw "192.168.1.1" to the LLM
// Sentinel sends:
{
  "indicator": "192.168.1.1",
  "semantic_context": "Private IP address (RFC1918 Class C). Not routable on public internet. Commonly used for home networks and small offices. No threat intelligence lookup applicable.",
  "classification": {
    "isPrivate": true,
    "isRoutable": false,
    "rfcClassification": "RFC1918 Class C Private"
  }
}
```

### Domain Analysis

Detects suspicious domain characteristics before LLM analysis:

- **Entropy calculation**: High entropy suggests DGA (Domain Generation Algorithm)
- **Punycode detection**: Identifies potential homoglyph attacks (`xn--80ak6aa92e.com` → `аррӏе.com`)
- **Typosquatting detection**: Compares against known brands
- **Age analysis**: Newly registered domains are higher risk

### Structured Output

All LLM responses follow a strict JSON schema:

```json
{
  "risk_score": 85,
  "confidence": 0.92,
  "classification": "malicious",
  "reasoning": "Multiple threat intelligence sources confirm this IP...",
  "suggested_actions": ["Block at firewall", "Search SIEM for historical connections"],
  "questions_for_analyst": ["Is this IP part of a known vendor's infrastructure?"]
}
```

## Kubernetes Security

Sentinel includes comprehensive Kubernetes security analysis:

### Manifest Scanning

Detects 15+ security issues including:

| Finding | Severity | Description |
|---------|----------|-------------|
| Privileged container | Critical | Container has full host access |
| Running as root | High | Container executes as UID 0 |
| Host network/PID/IPC | High | Shared namespaces with host |
| Dangerous capabilities | High | SYS_ADMIN, NET_ADMIN, etc. |
| Missing resource limits | Medium | DoS vulnerability |
| :latest image tag | Medium | Unpredictable deployments |
| Secrets in env vars | Medium | Credentials exposed in logs |

### Automatic Remediation

Generates fix suggestions and secure manifest examples:

```yaml
# Generated NetworkPolicy to block malicious IPs
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sentinel-block-malicious
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 185.220.101.0/24  # Known Tor exit nodes
              - 45.33.32.0/24     # Blocked range
```

## Project Structure

```
sentinel/
├── docs/
│   └── ARCHITECTURE.md      # Detailed system design
├── migrations/
│   └── 0001_initial_schema.sql
├── src/
│   ├── frontend/
│   │   └── Dashboard.jsx    # React UI
│   ├── lib/
│   │   ├── indicators.ts    # Indicator parsing & classification
│   │   └── k8s-security.ts  # Kubernetes security checks
│   ├── mcp/
│   │   └── server.js        # MCP server for Claude
│   └── workers/
│       └── index.ts         # Cloudflare Worker API
├── package.json
├── wrangler.toml            # Cloudflare config
└── README.md
```

## Cost Estimate

Running on Cloudflare's free/low-cost tiers:

| Service | Free Tier | Expected Usage | Cost |
|---------|-----------|----------------|------|
| Workers | 100K req/day | ~10K req/day | $0 |
| D1 | 5M rows read/day | ~50K rows/day | $0 |
| KV | 100K reads/day | ~20K reads/day | $0 |
| R2 | 10GB storage | ~1GB | $0 |
| **Total** | | | **$0-10/month** |

## Future Roadmap

- [ ] Browser extension for quick lookups
- [ ] STIX/TAXII export for threat intel sharing
- [ ] Webhook integrations (Slack, Teams, PagerDuty)
- [ ] Threat feed ingestion (URLhaus, Feodo Tracker)
- [ ] IOC correlation across historical analyses
- [ ] Team collaboration features

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.

## License

MIT License - see LICENSE file for details.

---

Built with ❤️ for the security community. Designed to demonstrate advanced security tooling for the Anthropic Security Engineer role.
# sentinel
