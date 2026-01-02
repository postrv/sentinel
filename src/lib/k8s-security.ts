/**
 * Sentinel K8s Security Module
 * 
 * Provides security analysis for Kubernetes manifests, RBAC auditing,
 * and automated NetworkPolicy generation.
 */

import * as yaml from 'yaml';

// ============================================================================
// TYPES
// ============================================================================

interface SecurityFinding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: 'privileges' | 'network' | 'secrets' | 'images' | 'resources' | 'config';
  title: string;
  description: string;
  remediation: string;
  references: string[];
  location?: string;
}

interface ManifestAnalysis {
  kind: string;
  name: string;
  namespace: string;
  findings: SecurityFinding[];
  riskScore: number;
  summary: string;
}

interface RBACAnalysis {
  overPrivilegedRoles: RoleIssue[];
  clusterAdminBindings: BindingIssue[];
  serviceAccountRisks: ServiceAccountIssue[];
  summary: string;
  riskScore: number;
}

interface RoleIssue {
  name: string;
  namespace: string;
  issue: string;
  severity: string;
  problematicRules: any[];
}

interface BindingIssue {
  name: string;
  subjects: string[];
  issue: string;
}

interface ServiceAccountIssue {
  name: string;
  namespace: string;
  issue: string;
  severity: string;
}

interface NetworkPolicySpec {
  name: string;
  namespace: string;
  podSelector: Record<string, string>;
  allowIngress?: IngressRule[];
  allowEgress?: EgressRule[];
  defaultDeny: boolean;
}

interface IngressRule {
  from: string;
  ports?: number[];
}

interface EgressRule {
  to: string;
  ports?: number[];
}

// ============================================================================
// SECURITY CHECKS
// ============================================================================

const SECURITY_CHECKS = {
  // Container security context checks
  runAsRoot: {
    severity: 'high' as const,
    category: 'privileges' as const,
    title: 'Container running as root',
    description: 'Container is configured to run as root user (UID 0). This provides unnecessary privileges and increases the blast radius of container escape vulnerabilities.',
    remediation: 'Set securityContext.runAsNonRoot: true and specify a non-zero runAsUser',
    references: ['https://kubernetes.io/docs/concepts/security/pod-security-standards/']
  },
  privilegedContainer: {
    severity: 'critical' as const,
    category: 'privileges' as const,
    title: 'Privileged container',
    description: 'Container is running in privileged mode, effectively giving it root access to the host. This completely bypasses container isolation.',
    remediation: 'Remove securityContext.privileged: true unless absolutely required for specific system operations',
    references: ['https://kubernetes.io/docs/concepts/security/pod-security-standards/']
  },
  hostNetwork: {
    severity: 'high' as const,
    category: 'network' as const,
    title: 'Host network namespace',
    description: 'Pod is using the host network namespace, allowing it to access all network interfaces on the host and potentially sniff traffic from other pods.',
    remediation: 'Remove hostNetwork: true unless required for network plugins or monitoring',
    references: ['https://kubernetes.io/docs/concepts/security/pod-security-standards/']
  },
  hostPID: {
    severity: 'high' as const,
    category: 'privileges' as const,
    title: 'Host PID namespace',
    description: 'Pod shares the host PID namespace, allowing it to see and potentially interact with host processes.',
    remediation: 'Remove hostPID: true',
    references: ['https://kubernetes.io/docs/concepts/security/pod-security-standards/']
  },
  hostIPC: {
    severity: 'medium' as const,
    category: 'privileges' as const,
    title: 'Host IPC namespace',
    description: 'Pod shares the host IPC namespace, allowing inter-process communication with host processes.',
    remediation: 'Remove hostIPC: true',
    references: ['https://kubernetes.io/docs/concepts/security/pod-security-standards/']
  },
  hostPath: {
    severity: 'high' as const,
    category: 'privileges' as const,
    title: 'HostPath volume mount',
    description: 'Pod mounts a host filesystem path. This can be used to escape container isolation or access sensitive host data.',
    remediation: 'Use alternative volume types (emptyDir, PVC) or restrict hostPath to read-only with specific allowed paths',
    references: ['https://kubernetes.io/docs/concepts/storage/volumes/#hostpath']
  },
  capabilityAll: {
    severity: 'critical' as const,
    category: 'privileges' as const,
    title: 'All capabilities added',
    description: 'Container has ALL Linux capabilities, equivalent to running as root with full host access.',
    remediation: 'Remove capabilities.add: ["ALL"] and add only required capabilities explicitly',
    references: ['https://man7.org/linux/man-pages/man7/capabilities.7.html']
  },
  dangerousCapabilities: {
    severity: 'high' as const,
    category: 'privileges' as const,
    title: 'Dangerous capabilities added',
    description: 'Container has dangerous Linux capabilities that could be used for privilege escalation.',
    remediation: 'Remove dangerous capabilities: SYS_ADMIN, SYS_PTRACE, NET_ADMIN unless absolutely required',
    references: ['https://man7.org/linux/man-pages/man7/capabilities.7.html']
  },
  noReadOnlyRoot: {
    severity: 'medium' as const,
    category: 'config' as const,
    title: 'Writable root filesystem',
    description: 'Container has a writable root filesystem, which could be exploited to modify binaries or install malware.',
    remediation: 'Set securityContext.readOnlyRootFilesystem: true and use emptyDir for writable paths',
    references: ['https://kubernetes.io/docs/concepts/security/pod-security-standards/']
  },
  allowPrivilegeEscalation: {
    severity: 'medium' as const,
    category: 'privileges' as const,
    title: 'Privilege escalation allowed',
    description: 'Container allows privilege escalation via setuid binaries or other mechanisms.',
    remediation: 'Set securityContext.allowPrivilegeEscalation: false',
    references: ['https://kubernetes.io/docs/concepts/security/pod-security-standards/']
  },
  noResourceLimits: {
    severity: 'medium' as const,
    category: 'resources' as const,
    title: 'No resource limits defined',
    description: 'Container has no resource limits, potentially allowing it to consume all node resources (DoS).',
    remediation: 'Define resources.limits for CPU and memory',
    references: ['https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/']
  },
  latestTag: {
    severity: 'medium' as const,
    category: 'images' as const,
    title: 'Using latest tag',
    description: 'Container image uses :latest tag, which is mutable and may pull unexpected versions.',
    remediation: 'Use specific image tags or digests (e.g., image:v1.2.3 or image@sha256:...)',
    references: ['https://kubernetes.io/docs/concepts/containers/images/']
  },
  noImageTag: {
    severity: 'medium' as const,
    category: 'images' as const,
    title: 'No image tag specified',
    description: 'Container image has no tag, defaulting to :latest which is mutable.',
    remediation: 'Specify explicit image tags or digests',
    references: ['https://kubernetes.io/docs/concepts/containers/images/']
  },
  secretInEnv: {
    severity: 'high' as const,
    category: 'secrets' as const,
    title: 'Secret exposed in environment variable',
    description: 'Secrets are exposed as environment variables, which may be leaked in logs, error messages, or /proc.',
    remediation: 'Mount secrets as files instead of environment variables when possible',
    references: ['https://kubernetes.io/docs/concepts/configuration/secret/']
  },
  automountServiceAccount: {
    severity: 'low' as const,
    category: 'config' as const,
    title: 'Service account token auto-mounted',
    description: 'Service account token is automatically mounted. If not needed, this expands the attack surface.',
    remediation: 'Set automountServiceAccountToken: false if the pod does not need to access the Kubernetes API',
    references: ['https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/']
  }
};

const DANGEROUS_CAPABILITIES = new Set([
  'SYS_ADMIN',
  'SYS_PTRACE', 
  'NET_ADMIN',
  'NET_RAW',
  'SYS_MODULE',
  'SYS_RAWIO',
  'SYS_BOOT',
  'MAC_ADMIN',
  'MAC_OVERRIDE',
  'SETFCAP',
  'MKNOD',
  'AUDIT_WRITE'
]);

// ============================================================================
// MANIFEST ANALYSIS
// ============================================================================

export function analyzeManifest(yamlContent: string): ManifestAnalysis[] {
  const results: ManifestAnalysis[] = [];
  
  // Parse YAML (may contain multiple documents)
  const documents = yaml.parseAllDocuments(yamlContent);
  
  for (const doc of documents) {
    if (!doc.contents) continue;
    
    const manifest = doc.toJSON();
    if (!manifest || !manifest.kind) continue;
    
    const analysis = analyzeResource(manifest);
    if (analysis) {
      results.push(analysis);
    }
  }
  
  return results;
}

function analyzeResource(manifest: any): ManifestAnalysis | null {
  const kind = manifest.kind;
  const name = manifest.metadata?.name || 'unnamed';
  const namespace = manifest.metadata?.namespace || 'default';
  
  const findings: SecurityFinding[] = [];
  
  // Extract pod spec based on resource type
  let podSpec: any = null;
  
  switch (kind) {
    case 'Pod':
      podSpec = manifest.spec;
      break;
    case 'Deployment':
    case 'DaemonSet':
    case 'StatefulSet':
    case 'ReplicaSet':
    case 'Job':
      podSpec = manifest.spec?.template?.spec;
      break;
    case 'CronJob':
      podSpec = manifest.spec?.jobTemplate?.spec?.template?.spec;
      break;
    default:
      // Not a workload resource
      return null;
  }
  
  if (!podSpec) return null;
  
  // Pod-level checks
  if (podSpec.hostNetwork === true) {
    findings.push({ ...SECURITY_CHECKS.hostNetwork, location: `${kind}/${name}` });
  }
  
  if (podSpec.hostPID === true) {
    findings.push({ ...SECURITY_CHECKS.hostPID, location: `${kind}/${name}` });
  }
  
  if (podSpec.hostIPC === true) {
    findings.push({ ...SECURITY_CHECKS.hostIPC, location: `${kind}/${name}` });
  }
  
  // Check for hostPath volumes
  const volumes = podSpec.volumes || [];
  for (const volume of volumes) {
    if (volume.hostPath) {
      findings.push({
        ...SECURITY_CHECKS.hostPath,
        location: `${kind}/${name}/volumes/${volume.name}`,
        description: `${SECURITY_CHECKS.hostPath.description} Path: ${volume.hostPath.path}`
      });
    }
  }
  
  // Service account auto-mount
  if (podSpec.automountServiceAccountToken !== false) {
    findings.push({ ...SECURITY_CHECKS.automountServiceAccount, location: `${kind}/${name}` });
  }
  
  // Container-level checks
  const containers = [
    ...(podSpec.containers || []),
    ...(podSpec.initContainers || [])
  ];
  
  for (const container of containers) {
    const containerPath = `${kind}/${name}/${container.name}`;
    const securityContext = container.securityContext || {};
    
    // Privileged check
    if (securityContext.privileged === true) {
      findings.push({ ...SECURITY_CHECKS.privilegedContainer, location: containerPath });
    }
    
    // Run as root check
    if (securityContext.runAsNonRoot !== true && securityContext.runAsUser !== 0) {
      // Only flag if not explicitly set to non-root
      if (securityContext.runAsUser === 0 || securityContext.runAsUser === undefined) {
        findings.push({ ...SECURITY_CHECKS.runAsRoot, location: containerPath });
      }
    }
    
    // Read-only root filesystem
    if (securityContext.readOnlyRootFilesystem !== true) {
      findings.push({ ...SECURITY_CHECKS.noReadOnlyRoot, location: containerPath });
    }
    
    // Privilege escalation
    if (securityContext.allowPrivilegeEscalation !== false) {
      findings.push({ ...SECURITY_CHECKS.allowPrivilegeEscalation, location: containerPath });
    }
    
    // Capabilities check
    const capabilities = securityContext.capabilities || {};
    const addedCaps = capabilities.add || [];
    
    if (addedCaps.includes('ALL')) {
      findings.push({ ...SECURITY_CHECKS.capabilityAll, location: containerPath });
    } else {
      const dangerous = addedCaps.filter((cap: string) => DANGEROUS_CAPABILITIES.has(cap));
      if (dangerous.length > 0) {
        findings.push({
          ...SECURITY_CHECKS.dangerousCapabilities,
          location: containerPath,
          description: `${SECURITY_CHECKS.dangerousCapabilities.description} Found: ${dangerous.join(', ')}`
        });
      }
    }
    
    // Resource limits
    if (!container.resources?.limits) {
      findings.push({ ...SECURITY_CHECKS.noResourceLimits, location: containerPath });
    }
    
    // Image tag check
    const image = container.image || '';
    if (image.endsWith(':latest')) {
      findings.push({ ...SECURITY_CHECKS.latestTag, location: containerPath });
    } else if (!image.includes(':') && !image.includes('@')) {
      findings.push({ ...SECURITY_CHECKS.noImageTag, location: containerPath });
    }
    
    // Secret in env check
    const envVars = container.env || [];
    for (const env of envVars) {
      if (env.valueFrom?.secretKeyRef) {
        findings.push({
          ...SECURITY_CHECKS.secretInEnv,
          location: `${containerPath}/env/${env.name}`,
          description: `Secret "${env.valueFrom.secretKeyRef.name}" exposed as env var "${env.name}"`
        });
      }
    }
  }
  
  // Calculate risk score
  const severityWeights = { critical: 25, high: 15, medium: 5, low: 2, info: 0 };
  let riskScore = findings.reduce((sum, f) => sum + severityWeights[f.severity], 0);
  riskScore = Math.min(100, riskScore);
  
  // Generate summary
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  
  let summary = `Found ${findings.length} security issues. `;
  if (criticalCount > 0) summary += `${criticalCount} critical. `;
  if (highCount > 0) summary += `${highCount} high. `;
  if (findings.length === 0) summary = 'No security issues found.';
  
  return {
    kind,
    name,
    namespace,
    findings,
    riskScore,
    summary
  };
}

// ============================================================================
// RBAC ANALYSIS  
// ============================================================================

export function analyzeRBAC(manifests: string): RBACAnalysis {
  const documents = yaml.parseAllDocuments(manifests);
  
  const roles: any[] = [];
  const clusterRoles: any[] = [];
  const roleBindings: any[] = [];
  const clusterRoleBindings: any[] = [];
  const serviceAccounts: any[] = [];
  
  for (const doc of documents) {
    if (!doc.contents) continue;
    const manifest = doc.toJSON();
    
    switch (manifest.kind) {
      case 'Role':
        roles.push(manifest);
        break;
      case 'ClusterRole':
        clusterRoles.push(manifest);
        break;
      case 'RoleBinding':
        roleBindings.push(manifest);
        break;
      case 'ClusterRoleBinding':
        clusterRoleBindings.push(manifest);
        break;
      case 'ServiceAccount':
        serviceAccounts.push(manifest);
        break;
    }
  }
  
  const overPrivilegedRoles: RoleIssue[] = [];
  const clusterAdminBindings: BindingIssue[] = [];
  const serviceAccountRisks: ServiceAccountIssue[] = [];
  
  // Check for overprivileged roles
  const dangerousVerbs = ['*', 'create', 'delete', 'patch', 'update'];
  const sensitiveResources = ['secrets', 'pods/exec', 'pods/attach', 'serviceaccounts', 'roles', 'clusterroles', 'rolebindings', 'clusterrolebindings'];
  
  for (const role of [...roles, ...clusterRoles]) {
    const problematicRules: any[] = [];
    
    for (const rule of (role.rules || [])) {
      const resources = rule.resources || [];
      const verbs = rule.verbs || [];
      
      // Wildcard everything
      if (resources.includes('*') && verbs.includes('*')) {
        problematicRules.push({
          rule,
          issue: 'Grants all permissions on all resources'
        });
        continue;
      }
      
      // Sensitive resource with dangerous verbs
      for (const resource of resources) {
        if (sensitiveResources.some(sr => resource.includes(sr))) {
          if (verbs.some((v: string) => dangerousVerbs.includes(v))) {
            problematicRules.push({
              rule,
              issue: `Grants ${verbs.join(',')} on sensitive resource: ${resource}`
            });
          }
        }
      }
    }
    
    if (problematicRules.length > 0) {
      overPrivilegedRoles.push({
        name: role.metadata?.name,
        namespace: role.metadata?.namespace || 'cluster-wide',
        issue: `Role has ${problematicRules.length} overprivileged rules`,
        severity: problematicRules.some(r => r.issue.includes('all permissions')) ? 'critical' : 'high',
        problematicRules
      });
    }
  }
  
  // Check for cluster-admin bindings
  for (const binding of clusterRoleBindings) {
    if (binding.roleRef?.name === 'cluster-admin') {
      const subjects = (binding.subjects || []).map((s: any) => 
        `${s.kind}:${s.namespace || ''}/${s.name}`
      );
      
      clusterAdminBindings.push({
        name: binding.metadata?.name,
        subjects,
        issue: 'Grants cluster-admin privileges'
      });
    }
  }
  
  // Check service accounts
  for (const sa of serviceAccounts) {
    // Check if SA has concerning bindings
    const saName = sa.metadata?.name;
    const saNamespace = sa.metadata?.namespace || 'default';
    
    const bindings = [...roleBindings, ...clusterRoleBindings].filter(b =>
      (b.subjects || []).some((s: any) => 
        s.kind === 'ServiceAccount' && 
        s.name === saName && 
        (s.namespace === saNamespace || !s.namespace)
      )
    );
    
    if (bindings.some(b => b.roleRef?.name === 'cluster-admin')) {
      serviceAccountRisks.push({
        name: saName,
        namespace: saNamespace,
        issue: 'Service account has cluster-admin privileges',
        severity: 'critical'
      });
    }
  }
  
  // Calculate risk score
  let riskScore = 0;
  riskScore += overPrivilegedRoles.filter(r => r.severity === 'critical').length * 25;
  riskScore += overPrivilegedRoles.filter(r => r.severity === 'high').length * 15;
  riskScore += clusterAdminBindings.length * 20;
  riskScore += serviceAccountRisks.filter(r => r.severity === 'critical').length * 25;
  riskScore = Math.min(100, riskScore);
  
  return {
    overPrivilegedRoles,
    clusterAdminBindings,
    serviceAccountRisks,
    summary: `Found ${overPrivilegedRoles.length} overprivileged roles, ${clusterAdminBindings.length} cluster-admin bindings, ${serviceAccountRisks.length} service account risks`,
    riskScore
  };
}

// ============================================================================
// NETWORK POLICY GENERATION
// ============================================================================

export function generateNetworkPolicy(spec: NetworkPolicySpec): string {
  const policy: any = {
    apiVersion: 'networking.k8s.io/v1',
    kind: 'NetworkPolicy',
    metadata: {
      name: spec.name,
      namespace: spec.namespace,
      labels: {
        'app.kubernetes.io/managed-by': 'sentinel',
        'sentinel.io/generated': new Date().toISOString()
      }
    },
    spec: {
      podSelector: {
        matchLabels: spec.podSelector
      },
      policyTypes: [] as string[]
    }
  };
  
  // Default deny
  if (spec.defaultDeny) {
    policy.spec.policyTypes = ['Ingress', 'Egress'];
    policy.spec.ingress = [];
    policy.spec.egress = [];
  }
  
  // Process ingress rules
  if (spec.allowIngress && spec.allowIngress.length > 0) {
    if (!policy.spec.policyTypes.includes('Ingress')) {
      policy.spec.policyTypes.push('Ingress');
    }
    
    policy.spec.ingress = spec.allowIngress.map(rule => {
      const ingressRule: any = { from: [] };
      
      if (rule.from === 'same-namespace') {
        ingressRule.from.push({
          podSelector: {}
        });
      } else if (rule.from.startsWith('namespace:')) {
        ingressRule.from.push({
          namespaceSelector: {
            matchLabels: {
              name: rule.from.replace('namespace:', '')
            }
          }
        });
      } else if (rule.from.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
        ingressRule.from.push({
          ipBlock: {
            cidr: rule.from.includes('/') ? rule.from : `${rule.from}/32`
          }
        });
      }
      
      if (rule.ports && rule.ports.length > 0) {
        ingressRule.ports = rule.ports.map(port => ({
          port,
          protocol: 'TCP'
        }));
      }
      
      return ingressRule;
    });
  }
  
  // Process egress rules
  if (spec.allowEgress && spec.allowEgress.length > 0) {
    if (!policy.spec.policyTypes.includes('Egress')) {
      policy.spec.policyTypes.push('Egress');
    }
    
    policy.spec.egress = spec.allowEgress.map(rule => {
      const egressRule: any = { to: [] };
      
      if (rule.to === 'dns') {
        // Allow DNS
        egressRule.to.push({
          namespaceSelector: {},
          podSelector: {
            matchLabels: {
              'k8s-app': 'kube-dns'
            }
          }
        });
        egressRule.ports = [{ port: 53, protocol: 'UDP' }, { port: 53, protocol: 'TCP' }];
      } else if (rule.to === 'same-namespace') {
        egressRule.to.push({
          podSelector: {}
        });
      } else if (rule.to.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
        egressRule.to.push({
          ipBlock: {
            cidr: rule.to.includes('/') ? rule.to : `${rule.to}/32`
          }
        });
      }
      
      if (rule.ports && rule.ports.length > 0 && !egressRule.ports) {
        egressRule.ports = rule.ports.map(port => ({
          port,
          protocol: 'TCP'
        }));
      }
      
      return egressRule;
    });
  }
  
  return yaml.stringify(policy);
}

// Generate a default deny-all policy
export function generateDefaultDenyPolicy(namespace: string): string {
  return generateNetworkPolicy({
    name: `default-deny-all`,
    namespace,
    podSelector: {},
    defaultDeny: true
  });
}

// Generate a policy to block specific malicious IPs
export function generateMaliciousIPBlockPolicy(
  namespace: string,
  maliciousIPs: string[],
  podSelector: Record<string, string> = {}
): string {
  // Create a policy that allows everything EXCEPT the malicious IPs
  const policy = {
    apiVersion: 'networking.k8s.io/v1',
    kind: 'NetworkPolicy',
    metadata: {
      name: 'block-malicious-ips',
      namespace,
      labels: {
        'app.kubernetes.io/managed-by': 'sentinel',
        'sentinel.io/type': 'malicious-ip-block'
      }
    },
    spec: {
      podSelector: Object.keys(podSelector).length > 0 ? { matchLabels: podSelector } : {},
      policyTypes: ['Egress'],
      egress: [{
        to: [{
          ipBlock: {
            cidr: '0.0.0.0/0',
            except: maliciousIPs.map(ip => ip.includes('/') ? ip : `${ip}/32`)
          }
        }]
      }]
    }
  };
  
  return yaml.stringify(policy);
}

// ============================================================================
// SEMANTIC CONTEXT FOR LLM
// ============================================================================

export function buildK8sSemanticContext(analysis: ManifestAnalysis[]): string {
  let context = `
=== KUBERNETES SECURITY ANALYSIS ===

RESOURCES ANALYZED: ${analysis.length}
TOTAL FINDINGS: ${analysis.reduce((sum, a) => sum + a.findings.length, 0)}
OVERALL RISK: ${Math.max(...analysis.map(a => a.riskScore))} / 100

`;

  for (const resource of analysis) {
    context += `
--- ${resource.kind}/${resource.name} (ns: ${resource.namespace}) ---
Risk Score: ${resource.riskScore}/100
Findings: ${resource.findings.length}

`;
    
    // Group by severity
    const bySeverity = {
      critical: resource.findings.filter(f => f.severity === 'critical'),
      high: resource.findings.filter(f => f.severity === 'high'),
      medium: resource.findings.filter(f => f.severity === 'medium'),
      low: resource.findings.filter(f => f.severity === 'low')
    };
    
    for (const [severity, findings] of Object.entries(bySeverity)) {
      if (findings.length === 0) continue;
      
      context += `${severity.toUpperCase()} (${findings.length}):\n`;
      for (const finding of findings) {
        context += `  • ${finding.title}\n`;
        context += `    ${finding.description}\n`;
        context += `    Fix: ${finding.remediation}\n\n`;
      }
    }
  }
  
  context += `
=== END KUBERNETES ANALYSIS ===
`;

  return context.trim();
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  SECURITY_CHECKS,
  DANGEROUS_CAPABILITIES
};

export type {
  SecurityFinding,
  ManifestAnalysis,
  RBACAnalysis,
  NetworkPolicySpec
};
