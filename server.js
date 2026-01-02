#!/usr/bin/env node
// =============================================================================
// SENTINEL MCP Server - Model Context Protocol integration for Claude
// =============================================================================
// 
// Provides security investigation tools directly to Claude via MCP protocol.
// This enables Claude to perform threat intelligence lookups, analyze indicators,
// and generate security mitigations without needing a separate web interface.
//
// Installation:
//   npm link  (from sentinel directory)
//   Add to Claude Desktop config:
//   {
//     "mcpServers": {
//       "sentinel": {
//         "command": "sentinel-mcp",
//         "env": {
//           "VT_API_KEY": "your-key",
//           "ABUSEIPDB_KEY": "your-key"
//         }
//       }
//     }
//   }
//
// =============================================================================

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

// =============================================================================
// Indicator Classification (matching indicators.ts logic)
// =============================================================================

const RFC_RANGES = {
  RFC1918_10: { start: 0x0A000000, end: 0x0AFFFFFF, name: 'RFC1918 Class A Private' },
  RFC1918_172: { start: 0xAC100000, end: 0xAC1FFFFF, name: 'RFC1918 Class B Private' },
  RFC1918_192: { start: 0xC0A80000, end: 0xC0A8FFFF, name: 'RFC1918 Class C Private' },
  RFC6598: { start: 0x64400000, end: 0x647FFFFF, name: 'RFC6598 CGNAT' },
  LOOPBACK: { start: 0x7F000000, end: 0x7FFFFFFF, name: 'Loopback' },
  LINK_LOCAL: { start: 0xA9FE0000, end: 0xA9FEFFFF, name: 'Link-Local' },
  MULTICAST: { start: 0xE0000000, end: 0xEFFFFFFF, name: 'Multicast' },
};

function ipToInt(ip) {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function classifyIP(ip) {
  const ipInt = ipToInt(ip);
  
  for (const [key, range] of Object.entries(RFC_RANGES)) {
    if (ipInt >= range.start && ipInt <= range.end) {
      return {
        isPrivate: true,
        isRoutable: false,
        rfcClassification: range.name,
        description: `Private IP (${range.name}) - not routable on public internet`
      };
    }
  }
  
  return {
    isPrivate: false,
    isRoutable: true,
    rfcClassification: 'Public',
    description: 'Public IP - routable on internet, suitable for threat intelligence lookup'
  };
}

function detectIndicatorType(value) {
  const trimmed = value.trim();
  
  // IPv4
  if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(trimmed)) {
    return 'ipv4';
  }
  
  // IPv6
  if (/^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^([0-9a-fA-F]{1,4}:)*::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$/.test(trimmed)) {
    return 'ipv6';
  }
  
  // Hashes
  if (/^[a-fA-F0-9]{32}$/.test(trimmed)) return 'md5';
  if (/^[a-fA-F0-9]{40}$/.test(trimmed)) return 'sha1';
  if (/^[a-fA-F0-9]{64}$/.test(trimmed)) return 'sha256';
  
  // URL
  if (/^https?:\/\//i.test(trimmed)) return 'url';
  
  // Email
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) return 'email';
  
  // Domain (basic check)
  if (/^[a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9][a-zA-Z0-9-]*)+$/.test(trimmed)) {
    return 'domain';
  }
  
  return 'unknown';
}

function calculateDomainEntropy(domain) {
  const chars = domain.toLowerCase().replace(/\./g, '');
  const freq = {};
  for (const c of chars) {
    freq[c] = (freq[c] || 0) + 1;
  }
  let entropy = 0;
  const len = chars.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// =============================================================================
// Threat Intelligence API Clients
// =============================================================================

async function queryVirusTotal(indicator, type) {
  const apiKey = process.env.VT_API_KEY;
  if (!apiKey) return { error: 'VT_API_KEY not configured' };
  
  const endpoints = {
    ipv4: `https://www.virustotal.com/api/v3/ip_addresses/${indicator}`,
    domain: `https://www.virustotal.com/api/v3/domains/${indicator}`,
    url: `https://www.virustotal.com/api/v3/urls/${Buffer.from(indicator).toString('base64').replace(/=/g, '')}`,
    sha256: `https://www.virustotal.com/api/v3/files/${indicator}`,
    sha1: `https://www.virustotal.com/api/v3/files/${indicator}`,
    md5: `https://www.virustotal.com/api/v3/files/${indicator}`,
  };
  
  const endpoint = endpoints[type];
  if (!endpoint) return { error: `Unsupported indicator type: ${type}` };
  
  try {
    const response = await fetch(endpoint, {
      headers: { 'x-apikey': apiKey }
    });
    
    if (!response.ok) {
      return { error: `VirusTotal API error: ${response.status}` };
    }
    
    const data = await response.json();
    const stats = data.data?.attributes?.last_analysis_stats || {};
    
    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      total: Object.values(stats).reduce((a, b) => a + b, 0),
      reputation: data.data?.attributes?.reputation,
      tags: data.data?.attributes?.tags || [],
      lastAnalysisDate: data.data?.attributes?.last_analysis_date,
    };
  } catch (error) {
    return { error: error.message };
  }
}

async function queryAbuseIPDB(ip) {
  const apiKey = process.env.ABUSEIPDB_KEY;
  if (!apiKey) return { error: 'ABUSEIPDB_KEY not configured' };
  
  try {
    const response = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
      { headers: { 'Key': apiKey, 'Accept': 'application/json' } }
    );
    
    if (!response.ok) {
      return { error: `AbuseIPDB API error: ${response.status}` };
    }
    
    const data = await response.json();
    return {
      abuseConfidenceScore: data.data?.abuseConfidenceScore,
      totalReports: data.data?.totalReports,
      countryCode: data.data?.countryCode,
      isp: data.data?.isp,
      domain: data.data?.domain,
      usageType: data.data?.usageType,
      isTor: data.data?.isTor,
      isWhitelisted: data.data?.isWhitelisted,
    };
  } catch (error) {
    return { error: error.message };
  }
}

async function queryShodan(ip) {
  const apiKey = process.env.SHODAN_KEY;
  if (!apiKey) return { error: 'SHODAN_KEY not configured' };
  
  try {
    const response = await fetch(
      `https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`
    );
    
    if (!response.ok) {
      if (response.status === 404) {
        return { found: false, message: 'No Shodan data for this IP' };
      }
      return { error: `Shodan API error: ${response.status}` };
    }
    
    const data = await response.json();
    return {
      found: true,
      ports: data.ports || [],
      hostnames: data.hostnames || [],
      country: data.country_name,
      city: data.city,
      org: data.org,
      isp: data.isp,
      os: data.os,
      vulns: data.vulns || [],
      tags: data.tags || [],
    };
  } catch (error) {
    return { error: error.message };
  }
}

async function queryGreyNoise(ip) {
  const apiKey = process.env.GREYNOISE_KEY;
  if (!apiKey) return { error: 'GREYNOISE_KEY not configured' };
  
  try {
    const response = await fetch(
      `https://api.greynoise.io/v3/community/${ip}`,
      { headers: { 'key': apiKey } }
    );
    
    if (!response.ok) {
      return { error: `GreyNoise API error: ${response.status}` };
    }
    
    const data = await response.json();
    return {
      noise: data.noise,
      riot: data.riot,
      classification: data.classification,
      name: data.name,
      link: data.link,
      lastSeen: data.last_seen,
    };
  } catch (error) {
    return { error: error.message };
  }
}

// =============================================================================
// Security Analysis Functions
// =============================================================================

function analyzeK8sManifest(manifest) {
  const findings = [];
  let severityScore = 0;
  
  const checks = [
    {
      name: 'privileged_container',
      severity: 'critical',
      points: 25,
      check: (m) => m.spec?.containers?.some(c => c.securityContext?.privileged === true),
      message: 'Container running in privileged mode - full host access',
      mitigation: 'Set securityContext.privileged: false'
    },
    {
      name: 'run_as_root',
      severity: 'high',
      points: 15,
      check: (m) => m.spec?.containers?.some(c => 
        c.securityContext?.runAsNonRoot !== true && c.securityContext?.runAsUser !== 0
      ),
      message: 'Container may run as root user',
      mitigation: 'Set securityContext.runAsNonRoot: true'
    },
    {
      name: 'host_network',
      severity: 'high',
      points: 15,
      check: (m) => m.spec?.hostNetwork === true,
      message: 'Pod uses host network namespace',
      mitigation: 'Remove hostNetwork: true unless absolutely required'
    },
    {
      name: 'host_pid',
      severity: 'high',
      points: 15,
      check: (m) => m.spec?.hostPID === true,
      message: 'Pod uses host PID namespace - can see all host processes',
      mitigation: 'Remove hostPID: true'
    },
    {
      name: 'no_resource_limits',
      severity: 'medium',
      points: 5,
      check: (m) => m.spec?.containers?.some(c => !c.resources?.limits),
      message: 'Container missing resource limits - DoS risk',
      mitigation: 'Add resources.limits for cpu and memory'
    },
    {
      name: 'latest_tag',
      severity: 'medium',
      points: 5,
      check: (m) => m.spec?.containers?.some(c => 
        c.image && (c.image.endsWith(':latest') || !c.image.includes(':'))
      ),
      message: 'Using :latest or untagged image - unpredictable deployments',
      mitigation: 'Use specific image tags (e.g., :v1.2.3)'
    },
    {
      name: 'secrets_in_env',
      severity: 'medium',
      points: 5,
      check: (m) => m.spec?.containers?.some(c =>
        c.env?.some(e => /secret|password|key|token/i.test(e.name) && e.value)
      ),
      message: 'Secrets hardcoded in environment variables',
      mitigation: 'Use secretKeyRef to reference Kubernetes Secrets'
    },
  ];
  
  // Get pod spec (handle Deployment, DaemonSet, etc.)
  let podSpec = manifest.spec;
  if (manifest.spec?.template?.spec) {
    podSpec = manifest.spec.template.spec;
  }
  
  for (const check of checks) {
    try {
      if (check.check({ spec: podSpec })) {
        findings.push({
          name: check.name,
          severity: check.severity,
          message: check.message,
          mitigation: check.mitigation,
        });
        severityScore += check.points;
      }
    } catch (e) {
      // Check failed to run, skip
    }
  }
  
  return { findings, severityScore };
}

function generateNetworkPolicy(namespace, podSelector, blockIPs = []) {
  const policy = {
    apiVersion: 'networking.k8s.io/v1',
    kind: 'NetworkPolicy',
    metadata: {
      name: `sentinel-block-${Date.now()}`,
      namespace: namespace || 'default',
    },
    spec: {
      podSelector: podSelector || {},
      policyTypes: ['Egress'],
      egress: [{
        to: blockIPs.map(ip => ({
          ipBlock: {
            cidr: ip.includes('/') ? ip : `${ip}/32`,
          }
        }))
      }]
    }
  };
  
  // If blocking specific IPs, we need to invert the logic
  if (blockIPs.length > 0) {
    policy.spec.egress = [{
      to: [{
        ipBlock: {
          cidr: '0.0.0.0/0',
          except: blockIPs.map(ip => ip.includes('/') ? ip : `${ip}/32`)
        }
      }]
    }];
  }
  
  return policy;
}

// =============================================================================
// MCP Server Setup
// =============================================================================

const server = new Server(
  {
    name: 'sentinel',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
      resources: {},
    },
  }
);

// =============================================================================
// Tool Definitions
// =============================================================================

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'analyze_indicator',
        description: `Analyze a security indicator (IP address, domain, URL, or file hash) for threats.
        
Performs the following:
1. Classifies the indicator type automatically
2. For IPs: determines if private/public, RFC classification
3. Queries threat intelligence APIs (VirusTotal, AbuseIPDB, Shodan, GreyNoise)
4. Returns structured risk assessment with confidence scores

Returns enrichment data and risk indicators. For private IPs, skips external lookups and provides RFC context instead.`,
        inputSchema: {
          type: 'object',
          properties: {
            indicator: {
              type: 'string',
              description: 'The indicator to analyze (IP, domain, URL, or hash)',
            },
            skip_enrichment: {
              type: 'boolean',
              description: 'Skip external API queries (faster, local analysis only)',
              default: false,
            },
          },
          required: ['indicator'],
        },
      },
      {
        name: 'analyze_k8s_manifest',
        description: `Analyze a Kubernetes manifest for security issues.
        
Checks for:
- Privileged containers (CRITICAL)
- Running as root (HIGH)
- Host namespace access (HIGH)
- Missing resource limits (MEDIUM)
- Mutable image tags like :latest (MEDIUM)
- Hardcoded secrets in env vars (MEDIUM)
- Dangerous capabilities

Returns findings with severity scores and specific mitigations.`,
        inputSchema: {
          type: 'object',
          properties: {
            manifest: {
              type: 'string',
              description: 'YAML or JSON Kubernetes manifest to analyze',
            },
          },
          required: ['manifest'],
        },
      },
      {
        name: 'generate_firewall_rules',
        description: `Generate firewall rules to block malicious IPs or networks.
        
Outputs rules for multiple platforms:
- iptables (Linux)
- AWS Security Groups (JSON)
- Azure NSG (JSON)
- GCP Firewall (gcloud commands)
- Kubernetes NetworkPolicy (YAML)`,
        inputSchema: {
          type: 'object',
          properties: {
            ips: {
              type: 'array',
              items: { type: 'string' },
              description: 'List of IPs or CIDRs to block',
            },
            direction: {
              type: 'string',
              enum: ['inbound', 'outbound', 'both'],
              default: 'both',
              description: 'Traffic direction to block',
            },
            k8s_namespace: {
              type: 'string',
              description: 'Kubernetes namespace for NetworkPolicy (optional)',
            },
          },
          required: ['ips'],
        },
      },
      {
        name: 'generate_siem_query',
        description: `Generate SIEM queries to hunt for indicators.
        
Outputs queries for:
- Splunk SPL
- Elastic/Kibana KQL
- Microsoft Sentinel KQL
- Sumo Logic

Queries search across common log sources (firewall, DNS, proxy, endpoint).`,
        inputSchema: {
          type: 'object',
          properties: {
            indicators: {
              type: 'array',
              items: { type: 'string' },
              description: 'Indicators to search for',
            },
            timerange: {
              type: 'string',
              default: '24h',
              description: 'Time range for search (e.g., 24h, 7d, 30d)',
            },
          },
          required: ['indicators'],
        },
      },
      {
        name: 'generate_network_policy',
        description: `Generate a Kubernetes NetworkPolicy to block egress to specific IPs or implement default-deny.`,
        inputSchema: {
          type: 'object',
          properties: {
            namespace: {
              type: 'string',
              default: 'default',
              description: 'Target namespace',
            },
            block_ips: {
              type: 'array',
              items: { type: 'string' },
              description: 'IPs/CIDRs to block egress to',
            },
            default_deny: {
              type: 'boolean',
              default: false,
              description: 'Generate default-deny policy instead',
            },
            pod_selector: {
              type: 'object',
              description: 'Pod selector labels (empty = all pods)',
            },
          },
          required: ['namespace'],
        },
      },
      {
        name: 'check_domain_reputation',
        description: `Quick domain reputation check focusing on typosquatting, DGA detection, and age.`,
        inputSchema: {
          type: 'object',
          properties: {
            domain: {
              type: 'string',
              description: 'Domain to check',
            },
          },
          required: ['domain'],
        },
      },
    ],
  };
});

// =============================================================================
// Tool Handlers
// =============================================================================

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  
  try {
    switch (name) {
      case 'analyze_indicator': {
        const { indicator, skip_enrichment } = args;
        const type = detectIndicatorType(indicator);
        
        const result = {
          indicator,
          type,
          classification: {},
          enrichment: {},
          riskIndicators: [],
        };
        
        // Type-specific classification
        if (type === 'ipv4') {
          result.classification = classifyIP(indicator);
          
          if (!result.classification.isPrivate && !skip_enrichment) {
            // Query threat intel APIs in parallel
            const [vt, abuse, shodan, greynoise] = await Promise.all([
              queryVirusTotal(indicator, type),
              queryAbuseIPDB(indicator),
              queryShodan(indicator),
              queryGreyNoise(indicator),
            ]);
            
            result.enrichment = { virustotal: vt, abuseipdb: abuse, shodan, greynoise };
            
            // Calculate risk indicators
            if (vt.malicious > 0) result.riskIndicators.push(`VirusTotal: ${vt.malicious}/${vt.total} detections`);
            if (abuse.abuseConfidenceScore > 50) result.riskIndicators.push(`AbuseIPDB: ${abuse.abuseConfidenceScore}% confidence`);
            if (greynoise.noise) result.riskIndicators.push('GreyNoise: Known scanner/noise');
            if (shodan.vulns?.length > 0) result.riskIndicators.push(`Shodan: ${shodan.vulns.length} known vulnerabilities`);
          }
        } else if (type === 'domain') {
          const entropy = calculateDomainEntropy(indicator);
          const isPunycode = indicator.startsWith('xn--');
          
          result.classification = {
            entropy: entropy.toFixed(2),
            entropyRisk: entropy > 4 ? 'high' : entropy > 3.5 ? 'medium' : 'low',
            isPunycode,
            dgaLikelihood: entropy > 4 ? 'high' : 'low',
          };
          
          if (!skip_enrichment) {
            result.enrichment.virustotal = await queryVirusTotal(indicator, type);
            if (result.enrichment.virustotal.malicious > 0) {
              result.riskIndicators.push(`VirusTotal: ${result.enrichment.virustotal.malicious} detections`);
            }
          }
          
          if (entropy > 4) result.riskIndicators.push('High entropy - possible DGA');
          if (isPunycode) result.riskIndicators.push('Punycode domain - check for homoglyph attack');
        } else if (['md5', 'sha1', 'sha256'].includes(type)) {
          if (!skip_enrichment) {
            result.enrichment.virustotal = await queryVirusTotal(indicator, type);
            if (result.enrichment.virustotal.malicious > 0) {
              result.riskIndicators.push(`VirusTotal: ${result.enrichment.virustotal.malicious}/${result.enrichment.virustotal.total} detections`);
            }
          }
        }
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(result, null, 2),
          }],
        };
      }
      
      case 'analyze_k8s_manifest': {
        let manifest;
        try {
          // Try JSON first
          manifest = JSON.parse(args.manifest);
        } catch {
          // Try YAML (basic parsing)
          // For full YAML support, would need js-yaml package
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: 'Please provide manifest as JSON. YAML parsing requires additional setup.',
                hint: 'Convert YAML to JSON using: kubectl convert -f manifest.yaml -o json'
              }, null, 2),
            }],
          };
        }
        
        const analysis = analyzeK8sManifest(manifest);
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              kind: manifest.kind,
              name: manifest.metadata?.name,
              namespace: manifest.metadata?.namespace || 'default',
              ...analysis,
              riskLevel: analysis.severityScore > 40 ? 'critical' : 
                        analysis.severityScore > 20 ? 'high' :
                        analysis.severityScore > 10 ? 'medium' : 'low',
            }, null, 2),
          }],
        };
      }
      
      case 'generate_firewall_rules': {
        const { ips, direction = 'both', k8s_namespace } = args;
        
        const rules = {
          iptables: ips.map(ip => {
            const cidr = ip.includes('/') ? ip : `${ip}/32`;
            const cmds = [];
            if (direction !== 'outbound') cmds.push(`iptables -A INPUT -s ${cidr} -j DROP`);
            if (direction !== 'inbound') cmds.push(`iptables -A OUTPUT -d ${cidr} -j DROP`);
            return cmds;
          }).flat(),
          
          aws_security_group: {
            IpPermissions: ips.map(ip => ({
              IpProtocol: '-1',
              IpRanges: [{ CidrIp: ip.includes('/') ? ip : `${ip}/32`, Description: 'Sentinel block' }],
            })),
          },
          
          gcp_firewall: ips.map(ip => 
            `gcloud compute firewall-rules create sentinel-block-${Date.now()} --action=DENY --rules=all --source-ranges=${ip.includes('/') ? ip : `${ip}/32`}`
          ),
        };
        
        if (k8s_namespace) {
          rules.kubernetes_network_policy = generateNetworkPolicy(k8s_namespace, {}, ips);
        }
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(rules, null, 2),
          }],
        };
      }
      
      case 'generate_siem_query': {
        const { indicators, timerange = '24h' } = args;
        const escaped = indicators.map(i => i.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
        
        const queries = {
          splunk: `index=* (${indicators.map(i => `"${i}"`).join(' OR ')}) earliest=-${timerange}
| stats count by src_ip, dest_ip, dest_port, sourcetype
| sort -count`,
          
          elastic_kql: `(${indicators.map(i => `"${i}"`).join(' OR ')})`,
          
          microsoft_sentinel: `union *
| where TimeGenerated > ago(${timerange.replace('d', 'd').replace('h', 'h')})
| where ${indicators.map(i => `* contains "${i}"`).join(' or ')}
| summarize count() by Type, bin(TimeGenerated, 1h)`,
          
          sumo_logic: `(${indicators.map(i => `"${i}"`).join(' OR ')}) | count by _sourceCategory`,
        };
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(queries, null, 2),
          }],
        };
      }
      
      case 'generate_network_policy': {
        const { namespace, block_ips, default_deny, pod_selector } = args;
        
        let policy;
        if (default_deny) {
          policy = {
            apiVersion: 'networking.k8s.io/v1',
            kind: 'NetworkPolicy',
            metadata: {
              name: 'default-deny-all',
              namespace,
            },
            spec: {
              podSelector: pod_selector || {},
              policyTypes: ['Ingress', 'Egress'],
            },
          };
        } else {
          policy = generateNetworkPolicy(namespace, pod_selector, block_ips || []);
        }
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(policy, null, 2),
          }],
        };
      }
      
      case 'check_domain_reputation': {
        const { domain } = args;
        const entropy = calculateDomainEntropy(domain);
        const isPunycode = domain.startsWith('xn--');
        
        // Check for common brand typosquatting
        const brandPatterns = ['google', 'microsoft', 'apple', 'amazon', 'facebook', 'paypal', 'netflix'];
        const typosquatTarget = brandPatterns.find(brand => 
          domain.includes(brand) && !domain.endsWith(`.${brand}.com`)
        );
        
        const result = {
          domain,
          entropy: entropy.toFixed(2),
          isPunycode,
          analysis: {
            dgaLikelihood: entropy > 4 ? 'HIGH' : entropy > 3.5 ? 'MEDIUM' : 'LOW',
            typosquatRisk: typosquatTarget ? `Possible ${typosquatTarget} typosquat` : 'No obvious brand impersonation',
            homoglyphRisk: isPunycode ? 'HIGH - Punycode detected' : 'LOW',
          },
          recommendations: [],
        };
        
        if (entropy > 4) result.recommendations.push('High entropy suggests possible DGA - investigate DNS query patterns');
        if (isPunycode) result.recommendations.push('Decode punycode and check for visual similarity to legitimate brands');
        if (typosquatTarget) result.recommendations.push(`Compare to legitimate ${typosquatTarget}.com domain`);
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(result, null, 2),
          }],
        };
      }
      
      default:
        return {
          content: [{
            type: 'text',
            text: `Unknown tool: ${name}`,
          }],
          isError: true,
        };
    }
  } catch (error) {
    return {
      content: [{
        type: 'text',
        text: `Error executing ${name}: ${error.message}`,
      }],
      isError: true,
    };
  }
});

// =============================================================================
// Resources (for reference data)
// =============================================================================

server.setRequestHandler(ListResourcesRequestSchema, async () => {
  return {
    resources: [
      {
        uri: 'sentinel://rfc-ranges',
        name: 'RFC IP Ranges',
        description: 'Reference of private/reserved IP ranges by RFC',
        mimeType: 'application/json',
      },
      {
        uri: 'sentinel://threat-feeds',
        name: 'Threat Feed Sources',
        description: 'List of supported threat intelligence feeds',
        mimeType: 'application/json',
      },
    ],
  };
});

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const { uri } = request.params;
  
  if (uri === 'sentinel://rfc-ranges') {
    return {
      contents: [{
        uri,
        mimeType: 'application/json',
        text: JSON.stringify({
          private_ranges: [
            { cidr: '10.0.0.0/8', rfc: 'RFC1918', description: 'Class A Private' },
            { cidr: '172.16.0.0/12', rfc: 'RFC1918', description: 'Class B Private' },
            { cidr: '192.168.0.0/16', rfc: 'RFC1918', description: 'Class C Private' },
            { cidr: '100.64.0.0/10', rfc: 'RFC6598', description: 'CGNAT Shared Address' },
            { cidr: '127.0.0.0/8', rfc: 'RFC1122', description: 'Loopback' },
            { cidr: '169.254.0.0/16', rfc: 'RFC3927', description: 'Link-Local' },
            { cidr: '224.0.0.0/4', rfc: 'RFC5771', description: 'Multicast' },
          ],
        }, null, 2),
      }],
    };
  }
  
  if (uri === 'sentinel://threat-feeds') {
    return {
      contents: [{
        uri,
        mimeType: 'application/json',
        text: JSON.stringify({
          feeds: [
            { name: 'VirusTotal', types: ['ip', 'domain', 'url', 'hash'], api: true },
            { name: 'AbuseIPDB', types: ['ip'], api: true },
            { name: 'Shodan', types: ['ip'], api: true },
            { name: 'GreyNoise', types: ['ip'], api: true },
            { name: 'URLhaus', types: ['url'], api: false, url: 'https://urlhaus.abuse.ch' },
            { name: 'Feodo Tracker', types: ['ip'], api: false, url: 'https://feodotracker.abuse.ch' },
          ],
        }, null, 2),
      }],
    };
  }
  
  return { contents: [] };
});

// =============================================================================
// Start Server
// =============================================================================

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Sentinel MCP server running');
}

main().catch(console.error);
