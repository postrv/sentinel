# Sentinel

**AI-Powered Threat Intelligence Analysis**

Analyze IP addresses, domains, URLs, and file hashes with AI-powered threat assessment. Sentinel combines data from multiple threat intelligence sources with Claude AI to provide actionable security insights.

[Live Demo](https://sentinel-app-cj5.pages.dev) | [API Documentation](#api-usage)

## Features

- **Instant Analysis** - Paste any indicator (IP, domain, URL, hash) and get comprehensive threat assessment
- **AI-Powered Insights** - Claude analyzes enrichment data to provide risk scores, reasoning, and recommended actions
- **Multi-Source Enrichment** - Aggregates data from VirusTotal, AbuseIPDB, Shodan, GreyNoise, and more
- **Ready-to-Use Mitigations** - Generates firewall rules, SIEM queries, and Kubernetes NetworkPolicies
- **Semantic Understanding** - Correctly identifies private IPs, RFC classifications, DGA domains, and punycode attacks

## Quick Start

### Web Interface

Visit [sentinel-app-cj5.pages.dev](https://sentinel-app-cj5.pages.dev) and enter any indicator to analyze.

**Try these examples:**
- `8.8.8.8` - Google DNS (benign)
- `185.220.101.1` - Known Tor exit node
- `xn--80ak6aa92e.com` - Punycode domain (potential homoglyph attack)
- `44d88612fea8a8f36de82e1278abb02f` - EICAR test file hash

### API Usage

```bash
# Analyze an IP address
curl -X POST https://sentinel.laurence-avent.workers.dev/api/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"indicator": "185.220.101.1"}'

# Analyze a domain
curl -X POST https://sentinel.laurence-avent.workers.dev/api/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"indicator": "suspicious-domain.xyz"}'

# Check API health
curl https://sentinel.laurence-avent.workers.dev/api/health
```

### Response Format

```json
{
  "indicator": "185.220.101.1",
  "type": "ip",
  "llmAnalysis": {
    "riskScore": 85,
    "confidence": 92,
    "classification": "malicious",
    "summary": "Known Tor exit node with multiple abuse reports...",
    "suggestedActions": [
      "Block at network perimeter",
      "Search SIEM for historical connections",
      "Review any authentication attempts from this IP"
    ],
    "questionsForAnalyst": [
      "Is Tor traffic expected in your environment?"
    ]
  },
  "enrichment": {
    "abuseipdb": { "abuseConfidenceScore": 100, "totalReports": 1247 },
    "shodan": { "ports": [80, 443, 9001], "org": "..." },
    "greynoise": { "noise": true, "classification": "malicious" }
  },
  "mitigations": {
    "firewallRules": ["iptables -A INPUT -s 185.220.101.1 -j DROP"],
    "siemQueries": ["index=* src_ip=\"185.220.101.1\" | stats count by dest_port"]
  }
}
```

## Rate Limits

| Tier | Requests/min | Requests/day |
|------|--------------|--------------|
| Free (unauthenticated) | 10 | 100 |
| API Key | 30 | 1,000 |

To request an API key, open an issue on this repository.

## Self-Hosting

### Prerequisites

- Node.js 18+
- Cloudflare account (free tier works)
- Anthropic API key

### Deploy Your Own

```bash
# Clone and install
git clone https://github.com/postrv/sentinel
cd sentinel
npm install

# Authenticate with Cloudflare
npx wrangler login

# Create resources
npx wrangler d1 create sentinel-db
npx wrangler kv:namespace create CACHE

# Update wrangler.toml with the IDs from above

# Run migrations
npm run db:migrate

# Set required secrets
npx wrangler secret put ANTHROPIC_API_KEY
npx wrangler secret put API_SECRET_KEY  # Generate with: openssl rand -hex 32

# Optional: Add threat intelligence API keys
npx wrangler secret put VT_API_KEY
npx wrangler secret put ABUSEIPDB_KEY
npx wrangler secret put SHODAN_KEY

# Deploy
npm run deploy
```

### Local Development

```bash
# Create local secrets file
cat > .dev.vars << EOF
ANTHROPIC_API_KEY=your-key-here
API_SECRET_KEY=dev-local-key-for-testing-only
EOF

# Run local migrations
npm run db:migrate:local

# Start dev server
npm run dev
# API available at http://localhost:8787
```

## Architecture

Sentinel runs on Cloudflare Workers with:
- **D1** - SQLite database for analysis history
- **KV** - Cache for rate limiting and API responses
- **Claude AI** - Threat analysis and reasoning

All threat intelligence lookups happen in parallel, and results are cached to minimize API calls.

## MCP Server (Claude Desktop)

Sentinel includes an MCP server for direct Claude Desktop integration:

```bash
npm link

# Add to Claude Desktop config
{
  "mcpServers": {
    "sentinel": {
      "command": "sentinel-mcp",
      "env": {
        "VT_API_KEY": "your-key",
        "SHODAN_KEY": "your-key"
      }
    }
  }
}
```

Available tools: `analyze_indicator`, `analyze_k8s_manifest`, `generate_firewall_rules`, `generate_siem_query`

## Contributing

Contributions welcome! Please open an issue first to discuss what you'd like to change.

## License

MIT
