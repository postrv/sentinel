/**
 * Mitigation Generation Service
 *
 * Generates firewall rules, DNS blocks, SIEM queries, and K8s policies.
 */

import type {
  Mitigations,
  EnrichmentData,
  ParsedIP,
  DomainStructure,
  URLAnalysis,
  HashAnalysis,
  IndicatorType,
} from '../types';

/**
 * Generate mitigations for an IP address
 */
function generateIPMitigations(
  ip: string,
  parsed: ParsedIP,
  _enrichment: EnrichmentData
): Mitigations {
  const mitigations: Mitigations = {
    firewallRules: [],
    dnsBlocks: [],
    siemQueries: [],
    k8sNetworkPolicies: [],
  };

  // Only generate firewall rules for routable IPs
  if (parsed.classification.isInternetRoutable) {
    mitigations.firewallRules = [
      `# iptables - Block IP`,
      `iptables -A INPUT -s ${ip} -j DROP`,
      `iptables -A OUTPUT -d ${ip} -j DROP`,
      ``,
      `# AWS Security Group (deny rule)`,
      `aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol all --source ${ip}/32`,
      ``,
      `# Azure NSG`,
      `az network nsg rule create --nsg-name MyNSG --name Block-${ip.replace(/\./g, '-')} --priority 100 --source-address-prefixes ${ip} --access Deny`,
      ``,
      `# GCP Firewall`,
      `gcloud compute firewall-rules create block-${ip.replace(/\./g, '-')} --action=DENY --source-ranges=${ip}/32 --priority=100`,
    ];

    // K8s NetworkPolicy
    mitigations.k8sNetworkPolicies = [
      `# Kubernetes NetworkPolicy to block IP`,
      `apiVersion: networking.k8s.io/v1`,
      `kind: NetworkPolicy`,
      `metadata:`,
      `  name: block-malicious-ip-${ip.replace(/\./g, '-')}`,
      `  namespace: default`,
      `spec:`,
      `  podSelector: {}`,
      `  policyTypes:`,
      `    - Egress`,
      `  egress:`,
      `    - to:`,
      `        - ipBlock:`,
      `            cidr: 0.0.0.0/0`,
      `            except:`,
      `              - ${ip}/32`,
    ];
  }

  mitigations.siemQueries = [
    `# Splunk`,
    `index=network (src_ip="${ip}" OR dest_ip="${ip}")`,
    ``,
    `# Elastic/Kibana`,
    `source.ip:"${ip}" OR destination.ip:"${ip}"`,
    ``,
    `# Microsoft Sentinel (KQL)`,
    `CommonSecurityLog | where SourceIP == "${ip}" or DestinationIP == "${ip}"`,
  ];

  return mitigations;
}

/**
 * Generate mitigations for a domain
 */
function generateDomainMitigations(
  _domain: string,
  parsed: DomainStructure,
  enrichment: EnrichmentData
): Mitigations {
  const mitigations: Mitigations = {
    firewallRules: [],
    dnsBlocks: [],
    siemQueries: [],
    k8sNetworkPolicies: [],
  };

  mitigations.dnsBlocks = [
    `# Pi-hole / AdGuard`,
    `${parsed.normalized}`,
    `*.${parsed.normalized}`,
    ``,
    `# BIND RPZ`,
    `${parsed.normalized} CNAME .`,
    `*.${parsed.normalized} CNAME .`,
    ``,
    `# Unbound`,
    `local-zone: "${parsed.normalized}" always_refuse`,
  ];

  mitigations.siemQueries = [
    `# Splunk (DNS logs)`,
    `index=dns query="${parsed.normalized}" OR query="*.${parsed.normalized}"`,
    ``,
    `# Elastic`,
    `dns.question.name:"${parsed.normalized}" OR dns.question.name:*.${parsed.normalized}`,
    ``,
    `# Microsoft Sentinel`,
    `DnsEvents | where Name contains "${parsed.normalized}"`,
  ];

  // Get resolved IPs for firewall rules
  if (enrichment.dns?.a && enrichment.dns.a.length > 0) {
    mitigations.firewallRules = enrichment.dns.a.map(
      ip => `# Block resolved IP: ${ip}\niptables -A OUTPUT -d ${ip} -j DROP`
    );
  }

  return mitigations;
}

/**
 * Generate mitigations for a URL
 */
function generateURLMitigations(
  url: string,
  parsed: URLAnalysis,
  _enrichment: EnrichmentData
): Mitigations {
  const mitigations: Mitigations = {
    firewallRules: [],
    dnsBlocks: [],
    siemQueries: [],
    k8sNetworkPolicies: [],
  };

  // Include domain blocks
  mitigations.dnsBlocks = [
    `# Block associated domain`,
    parsed.domain.normalized,
    `*.${parsed.domain.normalized}`,
  ];

  // Escape special regex characters for SIEM queries
  const escapedUrl = url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  mitigations.siemQueries = [
    `# Splunk (Web proxy logs)`,
    `index=proxy url="*${parsed.domain.normalized}*"`,
    ``,
    `# Elastic`,
    `url.domain:"${parsed.domain.normalized}"`,
    ``,
    `# URL in logs`,
    `*${escapedUrl}*`,
  ];

  return mitigations;
}

/**
 * Generate mitigations for a file hash
 */
function generateHashMitigations(
  hash: string,
  _parsed: HashAnalysis,
  _enrichment: EnrichmentData
): Mitigations {
  const mitigations: Mitigations = {
    firewallRules: [],
    dnsBlocks: [],
    siemQueries: [],
    k8sNetworkPolicies: [],
  };

  mitigations.siemQueries = [
    `# Splunk (endpoint logs)`,
    `index=endpoint (file_hash="${hash}" OR md5="${hash}" OR sha256="${hash}")`,
    ``,
    `# Carbon Black`,
    `process_hash:${hash}`,
    ``,
    `# CrowdStrike Falcon`,
    `FileHash:"${hash}"`,
    ``,
    `# Microsoft Defender`,
    `DeviceFileEvents | where SHA256 == "${hash}" or MD5 == "${hash}"`,
  ];

  return mitigations;
}

/**
 * Generate mitigations based on indicator type
 */
export function generateMitigations(
  indicator: string,
  type: IndicatorType,
  parsed: ParsedIP | DomainStructure | URLAnalysis | HashAnalysis,
  enrichment: EnrichmentData
): Mitigations {
  switch (type) {
    case 'ip':
      return generateIPMitigations(indicator, parsed as ParsedIP, enrichment);
    case 'domain':
      return generateDomainMitigations(indicator, parsed as DomainStructure, enrichment);
    case 'url':
      return generateURLMitigations(indicator, parsed as URLAnalysis, enrichment);
    case 'hash':
      return generateHashMitigations(indicator, parsed as HashAnalysis, enrichment);
    default:
      return {
        firewallRules: [],
        dnsBlocks: [],
        siemQueries: [],
        k8sNetworkPolicies: [],
      };
  }
}

/**
 * Generate multiple firewall rules for a list of IPs
 */
export function generateBulkFirewallRules(
  ips: string[],
  direction: 'inbound' | 'outbound' | 'both' = 'both'
): {
  iptables: string[];
  awsSecurityGroup: object;
  gcpFirewall: string[];
} {
  const iptables: string[] = [];
  const awsRules: object[] = [];
  const gcpFirewall: string[] = [];

  for (const ip of ips) {
    const cidr = ip.includes('/') ? ip : `${ip}/32`;
    const safeName = ip.replace(/[.\/]/g, '-');

    if (direction !== 'outbound') {
      iptables.push(`iptables -A INPUT -s ${cidr} -j DROP`);
    }
    if (direction !== 'inbound') {
      iptables.push(`iptables -A OUTPUT -d ${cidr} -j DROP`);
    }

    awsRules.push({
      IpProtocol: '-1',
      IpRanges: [{ CidrIp: cidr, Description: `Sentinel block: ${ip}` }],
    });

    gcpFirewall.push(
      `gcloud compute firewall-rules create sentinel-block-${safeName} --action=DENY --rules=all --source-ranges=${cidr}`
    );
  }

  return {
    iptables,
    awsSecurityGroup: { IpPermissions: awsRules },
    gcpFirewall,
  };
}

/**
 * Generate SIEM queries for multiple indicators
 */
export function generateBulkSIEMQueries(
  indicators: string[],
  timeRange: string = '24h'
): {
  splunk: string;
  elastic: string;
  sentinel: string;
} {
  const escaped = indicators.map(i => `"${i}"`);
  const orClause = escaped.join(' OR ');

  return {
    splunk: `index=* (${orClause}) earliest=-${timeRange}
| stats count by src_ip, dest_ip, dest_port, sourcetype
| sort -count`,

    elastic: `(${orClause})`,

    sentinel: `union *
| where TimeGenerated > ago(${timeRange})
| where ${indicators.map(i => `* contains "${i}"`).join(' or ')}
| summarize count() by Type, bin(TimeGenerated, 1h)`,
  };
}
