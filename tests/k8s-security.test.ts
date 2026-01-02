import { describe, it, expect } from 'vitest';
import {
  analyzeManifest,
  analyzeRBAC,
  generateNetworkPolicy,
  generateDefaultDenyPolicy,
  generateMaliciousIPBlockPolicy,
  buildK8sSemanticContext,
  SECURITY_CHECKS,
  DANGEROUS_CAPABILITIES,
} from '../src/lib/k8s-security';
import * as yaml from 'yaml';

// =============================================================================
// MANIFEST ANALYSIS TESTS
// =============================================================================

describe('analyzeManifest', () => {
  describe('Pod analysis', () => {
    it('should detect privileged container', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
    - name: app
      image: nginx:1.21
      securityContext:
        privileged: true
`;
      const results = analyzeManifest(manifest);
      expect(results).toHaveLength(1);
      expect(results[0].findings.some(f => f.title === 'Privileged container')).toBe(true);
      expect(results[0].riskScore).toBeGreaterThanOrEqual(25);
    });

    it('should detect running as root when no securityContext is set', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: root-pod
spec:
  containers:
    - name: app
      image: nginx:1.21
`;
      const results = analyzeManifest(manifest);
      expect(results).toHaveLength(1);
      // The check flags containers that don't explicitly set runAsNonRoot: true
      expect(results[0].findings.some(f => f.title === 'Container running as root')).toBe(true);
    });

    it('should detect host network usage', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: host-net-pod
spec:
  hostNetwork: true
  containers:
    - name: app
      image: nginx:1.21
`;
      const results = analyzeManifest(manifest);
      expect(results[0].findings.some(f => f.title === 'Host network namespace')).toBe(true);
    });

    it('should detect host PID namespace', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: host-pid-pod
spec:
  hostPID: true
  containers:
    - name: app
      image: nginx:1.21
`;
      const results = analyzeManifest(manifest);
      expect(results[0].findings.some(f => f.title === 'Host PID namespace')).toBe(true);
    });

    it('should detect host IPC namespace', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: host-ipc-pod
spec:
  hostIPC: true
  containers:
    - name: app
      image: nginx:1.21
`;
      const results = analyzeManifest(manifest);
      expect(results[0].findings.some(f => f.title === 'Host IPC namespace')).toBe(true);
    });

    it('should detect hostPath volume mounts', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-pod
spec:
  containers:
    - name: app
      image: nginx:1.21
      volumeMounts:
        - name: host-volume
          mountPath: /host
  volumes:
    - name: host-volume
      hostPath:
        path: /etc
`;
      const results = analyzeManifest(manifest);
      expect(results[0].findings.some(f => f.title === 'HostPath volume mount')).toBe(true);
    });

    it('should detect missing resource limits', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: no-limits-pod
spec:
  containers:
    - name: app
      image: nginx:1.21
`;
      const results = analyzeManifest(manifest);
      expect(results[0].findings.some(f => f.title === 'No resource limits defined')).toBe(true);
    });

    it('should detect :latest tag', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: latest-pod
spec:
  containers:
    - name: app
      image: nginx:latest
`;
      const results = analyzeManifest(manifest);
      expect(results[0].findings.some(f => f.title === 'Using latest tag')).toBe(true);
    });

    it('should detect no image tag', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: untagged-pod
spec:
  containers:
    - name: app
      image: nginx
`;
      const results = analyzeManifest(manifest);
      expect(results[0].findings.some(f => f.title === 'No image tag specified')).toBe(true);
    });

    it('should detect secrets in environment variables', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: secret-env-pod
spec:
  containers:
    - name: app
      image: nginx:1.21
      env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secrets
              key: password
`;
      const results = analyzeManifest(manifest);
      expect(results[0].findings.some(f => f.title === 'Secret exposed in environment variable')).toBe(true);
    });

    it('should detect ALL capabilities', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: all-caps-pod
spec:
  containers:
    - name: app
      image: nginx:1.21
      securityContext:
        capabilities:
          add: ["ALL"]
`;
      const results = analyzeManifest(manifest);
      expect(results[0].findings.some(f => f.title === 'All capabilities added')).toBe(true);
    });

    it('should detect dangerous capabilities', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: dangerous-caps-pod
spec:
  containers:
    - name: app
      image: nginx:1.21
      securityContext:
        capabilities:
          add: ["SYS_ADMIN", "NET_ADMIN"]
`;
      const results = analyzeManifest(manifest);
      expect(results[0].findings.some(f => f.title === 'Dangerous capabilities added')).toBe(true);
    });

    it('should detect writable root filesystem', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: writable-root-pod
spec:
  containers:
    - name: app
      image: nginx:1.21
`;
      const results = analyzeManifest(manifest);
      expect(results[0].findings.some(f => f.title === 'Writable root filesystem')).toBe(true);
    });

    it('should detect privilege escalation allowed', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: priv-esc-pod
spec:
  containers:
    - name: app
      image: nginx:1.21
`;
      const results = analyzeManifest(manifest);
      expect(results[0].findings.some(f => f.title === 'Privilege escalation allowed')).toBe(true);
    });

    it('should detect auto-mounted service account token', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: sa-mount-pod
spec:
  containers:
    - name: app
      image: nginx:1.21
`;
      const results = analyzeManifest(manifest);
      expect(results[0].findings.some(f => f.title === 'Service account token auto-mounted')).toBe(true);
    });

    it('should pass secure Pod configuration', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: nginx:1.21.0
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
      resources:
        limits:
          cpu: "100m"
          memory: "128Mi"
`;
      const results = analyzeManifest(manifest);
      expect(results[0].riskScore).toBe(0);
      expect(results[0].findings).toHaveLength(0);
    });
  });

  describe('Deployment analysis', () => {
    it('should analyze Deployment pod template', () => {
      const manifest = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: privileged-deployment
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
        - name: app
          image: nginx:1.21
          securityContext:
            privileged: true
`;
      const results = analyzeManifest(manifest);
      expect(results).toHaveLength(1);
      expect(results[0].kind).toBe('Deployment');
      expect(results[0].findings.some(f => f.title === 'Privileged container')).toBe(true);
    });
  });

  describe('DaemonSet analysis', () => {
    it('should analyze DaemonSet pod template', () => {
      const manifest = `
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: host-network-daemonset
spec:
  selector:
    matchLabels:
      app: agent
  template:
    metadata:
      labels:
        app: agent
    spec:
      hostNetwork: true
      containers:
        - name: agent
          image: agent:1.0
`;
      const results = analyzeManifest(manifest);
      expect(results[0].kind).toBe('DaemonSet');
      expect(results[0].findings.some(f => f.title === 'Host network namespace')).toBe(true);
    });
  });

  describe('StatefulSet analysis', () => {
    it('should analyze StatefulSet pod template', () => {
      const manifest = `
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db-statefulset
spec:
  serviceName: db
  replicas: 3
  selector:
    matchLabels:
      app: db
  template:
    metadata:
      labels:
        app: db
    spec:
      containers:
        - name: db
          image: postgres
`;
      const results = analyzeManifest(manifest);
      expect(results[0].kind).toBe('StatefulSet');
      expect(results[0].findings.some(f => f.title === 'No image tag specified')).toBe(true);
    });
  });

  describe('CronJob analysis', () => {
    it('should analyze CronJob pod template', () => {
      const manifest = `
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup-job
spec:
  schedule: "0 1 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: backup
              image: backup:latest
          restartPolicy: OnFailure
`;
      const results = analyzeManifest(manifest);
      expect(results[0].kind).toBe('CronJob');
      expect(results[0].findings.some(f => f.title === 'Using latest tag')).toBe(true);
    });
  });

  describe('Multi-document YAML', () => {
    it('should analyze multiple resources in one YAML', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: pod1
spec:
  containers:
    - name: app
      image: nginx:1.21
---
apiVersion: v1
kind: Pod
metadata:
  name: pod2
spec:
  hostNetwork: true
  containers:
    - name: app
      image: nginx:1.21
`;
      const results = analyzeManifest(manifest);
      expect(results).toHaveLength(2);
      expect(results[0].name).toBe('pod1');
      expect(results[1].name).toBe('pod2');
      expect(results[1].findings.some(f => f.title === 'Host network namespace')).toBe(true);
    });
  });

  describe('Init containers', () => {
    it('should analyze init containers', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: init-pod
spec:
  initContainers:
    - name: init
      image: busybox:latest
      securityContext:
        privileged: true
  containers:
    - name: app
      image: nginx:1.21
`;
      const results = analyzeManifest(manifest);
      // Should detect both init container issues and main container issues
      expect(results[0].findings.some(f =>
        f.title === 'Privileged container' && f.location?.includes('init')
      )).toBe(true);
    });
  });

  describe('Risk score calculation', () => {
    it('should calculate higher score for critical findings', () => {
      const criticalManifest = `
apiVersion: v1
kind: Pod
metadata:
  name: critical-pod
spec:
  containers:
    - name: app
      image: nginx:1.21
      securityContext:
        privileged: true
`;
      const mediumManifest = `
apiVersion: v1
kind: Pod
metadata:
  name: medium-pod
spec:
  containers:
    - name: app
      image: nginx:latest
`;
      const criticalResults = analyzeManifest(criticalManifest);
      const mediumResults = analyzeManifest(mediumManifest);

      expect(criticalResults[0].riskScore).toBeGreaterThan(mediumResults[0].riskScore);
    });

    it('should cap risk score at 100', () => {
      const manifest = `
apiVersion: v1
kind: Pod
metadata:
  name: very-insecure-pod
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
    - name: app
      image: nginx:latest
      securityContext:
        privileged: true
        capabilities:
          add: ["ALL"]
`;
      const results = analyzeManifest(manifest);
      expect(results[0].riskScore).toBeLessThanOrEqual(100);
    });
  });
});

// =============================================================================
// RBAC ANALYSIS TESTS
// =============================================================================

describe('analyzeRBAC', () => {
  it('should detect overprivileged ClusterRole with wildcard', () => {
    const manifest = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: super-admin
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
`;
    const result = analyzeRBAC(manifest);
    expect(result.overPrivilegedRoles.length).toBeGreaterThan(0);
    expect(result.overPrivilegedRoles[0].name).toBe('super-admin');
    expect(result.overPrivilegedRoles[0].severity).toBe('critical');
  });

  it('should detect role with access to secrets', () => {
    const manifest = `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch", "create", "delete"]
`;
    const result = analyzeRBAC(manifest);
    expect(result.overPrivilegedRoles.some(r => r.name === 'secret-reader')).toBe(true);
  });

  it('should detect cluster-admin ClusterRoleBinding', () => {
    const manifest = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: admin-sa
    namespace: default
`;
    const result = analyzeRBAC(manifest);
    expect(result.clusterAdminBindings.length).toBeGreaterThan(0);
    expect(result.clusterAdminBindings[0].name).toBe('admin-binding');
  });

  it('should detect service account with cluster-admin', () => {
    const manifest = `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-sa
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: admin-sa
    namespace: default
`;
    const result = analyzeRBAC(manifest);
    expect(result.serviceAccountRisks.some(sa => sa.name === 'admin-sa')).toBe(true);
    expect(result.serviceAccountRisks.some(sa => sa.severity === 'critical')).toBe(true);
  });

  it('should generate summary with counts', () => {
    const manifest = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: super-admin
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
`;
    const result = analyzeRBAC(manifest);
    expect(result.summary).toContain('overprivileged roles');
  });

  it('should calculate risk score', () => {
    const manifest = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: admin-sa
    namespace: default
`;
    const result = analyzeRBAC(manifest);
    expect(result.riskScore).toBeGreaterThan(0);
  });
});

// =============================================================================
// NETWORK POLICY GENERATION TESTS
// =============================================================================

describe('generateNetworkPolicy', () => {
  it('should generate default-deny policy', () => {
    const policy = generateNetworkPolicy({
      name: 'default-deny',
      namespace: 'production',
      podSelector: {},
      defaultDeny: true,
    });

    const parsed = yaml.parse(policy);
    expect(parsed.kind).toBe('NetworkPolicy');
    expect(parsed.metadata.name).toBe('default-deny');
    expect(parsed.metadata.namespace).toBe('production');
    expect(parsed.spec.policyTypes).toContain('Ingress');
    expect(parsed.spec.policyTypes).toContain('Egress');
  });

  it('should generate policy with ingress rules', () => {
    const policy = generateNetworkPolicy({
      name: 'allow-web',
      namespace: 'default',
      podSelector: { app: 'web' },
      allowIngress: [
        { from: 'same-namespace', ports: [80, 443] },
      ],
      defaultDeny: false,
    });

    const parsed = yaml.parse(policy);
    expect(parsed.spec.podSelector.matchLabels.app).toBe('web');
    expect(parsed.spec.ingress[0].ports).toHaveLength(2);
  });

  it('should generate policy with namespace selector', () => {
    const policy = generateNetworkPolicy({
      name: 'allow-from-ns',
      namespace: 'default',
      podSelector: { app: 'api' },
      allowIngress: [
        { from: 'namespace:frontend', ports: [8080] },
      ],
      defaultDeny: false,
    });

    const parsed = yaml.parse(policy);
    expect(parsed.spec.ingress[0].from[0].namespaceSelector.matchLabels.name).toBe('frontend');
  });

  it('should generate policy with IP block', () => {
    const policy = generateNetworkPolicy({
      name: 'allow-external',
      namespace: 'default',
      podSelector: { app: 'api' },
      allowIngress: [
        { from: '10.0.0.0/8', ports: [443] },
      ],
      defaultDeny: false,
    });

    const parsed = yaml.parse(policy);
    expect(parsed.spec.ingress[0].from[0].ipBlock.cidr).toBe('10.0.0.0/8');
  });

  it('should generate policy with egress to DNS', () => {
    const policy = generateNetworkPolicy({
      name: 'allow-dns',
      namespace: 'default',
      podSelector: {},
      allowEgress: [
        { to: 'dns' },
      ],
      defaultDeny: false,
    });

    const parsed = yaml.parse(policy);
    expect(parsed.spec.egress[0].ports).toContainEqual({ port: 53, protocol: 'UDP' });
    expect(parsed.spec.egress[0].ports).toContainEqual({ port: 53, protocol: 'TCP' });
  });

  it('should add Sentinel labels', () => {
    const policy = generateNetworkPolicy({
      name: 'test-policy',
      namespace: 'default',
      podSelector: {},
      defaultDeny: true,
    });

    const parsed = yaml.parse(policy);
    expect(parsed.metadata.labels['app.kubernetes.io/managed-by']).toBe('sentinel');
    expect(parsed.metadata.labels['sentinel.io/generated']).toBeDefined();
  });
});

describe('generateDefaultDenyPolicy', () => {
  it('should generate a default-deny-all policy', () => {
    const policy = generateDefaultDenyPolicy('production');
    const parsed = yaml.parse(policy);

    expect(parsed.metadata.name).toBe('default-deny-all');
    expect(parsed.metadata.namespace).toBe('production');
    expect(parsed.spec.podSelector).toEqual({ matchLabels: {} });
    expect(parsed.spec.policyTypes).toContain('Ingress');
    expect(parsed.spec.policyTypes).toContain('Egress');
  });
});

describe('generateMaliciousIPBlockPolicy', () => {
  it('should generate policy to block malicious IPs', () => {
    const policy = generateMaliciousIPBlockPolicy('default', [
      '192.168.1.100',
      '10.0.0.50/24',
    ]);

    const parsed = yaml.parse(policy);
    expect(parsed.metadata.name).toBe('block-malicious-ips');
    expect(parsed.spec.policyTypes).toContain('Egress');
    expect(parsed.spec.egress[0].to[0].ipBlock.except).toContain('192.168.1.100/32');
    expect(parsed.spec.egress[0].to[0].ipBlock.except).toContain('10.0.0.50/24');
  });

  it('should support pod selector', () => {
    const policy = generateMaliciousIPBlockPolicy(
      'default',
      ['192.168.1.100'],
      { app: 'web' }
    );

    const parsed = yaml.parse(policy);
    expect(parsed.spec.podSelector.matchLabels.app).toBe('web');
  });

  it('should add Sentinel labels', () => {
    const policy = generateMaliciousIPBlockPolicy('default', ['192.168.1.100']);
    const parsed = yaml.parse(policy);

    expect(parsed.metadata.labels['sentinel.io/type']).toBe('malicious-ip-block');
  });
});

// =============================================================================
// SEMANTIC CONTEXT TESTS
// =============================================================================

describe('buildK8sSemanticContext', () => {
  it('should generate semantic context from analysis', () => {
    const analysis = [
      {
        kind: 'Deployment',
        name: 'web-app',
        namespace: 'production',
        findings: [
          {
            severity: 'critical' as const,
            category: 'privileges' as const,
            title: 'Privileged container',
            description: 'Container running in privileged mode',
            remediation: 'Remove privileged: true',
            references: [],
          },
        ],
        riskScore: 25,
        summary: 'Found 1 security issue',
      },
    ];

    const context = buildK8sSemanticContext(analysis);
    expect(context).toContain('KUBERNETES SECURITY ANALYSIS');
    expect(context).toContain('Deployment/web-app');
    expect(context).toContain('production');
    expect(context).toContain('CRITICAL');
    expect(context).toContain('Privileged container');
  });

  it('should group findings by severity', () => {
    const analysis = [
      {
        kind: 'Pod',
        name: 'test-pod',
        namespace: 'default',
        findings: [
          {
            severity: 'high' as const,
            category: 'privileges' as const,
            title: 'High Issue',
            description: 'High severity issue',
            remediation: 'Fix it',
            references: [],
          },
          {
            severity: 'medium' as const,
            category: 'config' as const,
            title: 'Medium Issue',
            description: 'Medium severity issue',
            remediation: 'Fix it too',
            references: [],
          },
        ],
        riskScore: 20,
        summary: 'Found 2 issues',
      },
    ];

    const context = buildK8sSemanticContext(analysis);
    expect(context).toContain('HIGH');
    expect(context).toContain('MEDIUM');
  });
});

// =============================================================================
// SECURITY CHECKS CONSTANTS TESTS
// =============================================================================

describe('SECURITY_CHECKS', () => {
  it('should have all expected checks', () => {
    expect(SECURITY_CHECKS.privilegedContainer).toBeDefined();
    expect(SECURITY_CHECKS.runAsRoot).toBeDefined();
    expect(SECURITY_CHECKS.hostNetwork).toBeDefined();
    expect(SECURITY_CHECKS.hostPID).toBeDefined();
    expect(SECURITY_CHECKS.hostIPC).toBeDefined();
    expect(SECURITY_CHECKS.hostPath).toBeDefined();
    expect(SECURITY_CHECKS.noResourceLimits).toBeDefined();
    expect(SECURITY_CHECKS.latestTag).toBeDefined();
    expect(SECURITY_CHECKS.secretInEnv).toBeDefined();
  });

  it('should have valid severity levels', () => {
    const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
    Object.values(SECURITY_CHECKS).forEach(check => {
      expect(validSeverities).toContain(check.severity);
    });
  });

  it('should have valid categories', () => {
    const validCategories = ['privileges', 'network', 'secrets', 'images', 'resources', 'config'];
    Object.values(SECURITY_CHECKS).forEach(check => {
      expect(validCategories).toContain(check.category);
    });
  });

  it('should have remediation for each check', () => {
    Object.values(SECURITY_CHECKS).forEach(check => {
      expect(check.remediation).toBeDefined();
      expect(check.remediation.length).toBeGreaterThan(0);
    });
  });
});

describe('DANGEROUS_CAPABILITIES', () => {
  it('should contain known dangerous capabilities', () => {
    expect(DANGEROUS_CAPABILITIES.has('SYS_ADMIN')).toBe(true);
    expect(DANGEROUS_CAPABILITIES.has('SYS_PTRACE')).toBe(true);
    expect(DANGEROUS_CAPABILITIES.has('NET_ADMIN')).toBe(true);
    expect(DANGEROUS_CAPABILITIES.has('NET_RAW')).toBe(true);
  });

  it('should not contain safe capabilities', () => {
    expect(DANGEROUS_CAPABILITIES.has('NET_BIND_SERVICE')).toBe(false);
    expect(DANGEROUS_CAPABILITIES.has('CHOWN')).toBe(false);
  });
});
