import React, { useState, useCallback } from 'react';

// ============================================================================
// TYPES
// ============================================================================

interface AnalysisResult {
  indicator: string;
  type: 'ip' | 'domain' | 'url' | 'hash';
  parsed: any;
  enrichment: any;
  llmAnalysis: {
    summary: string;
    riskScore: number;
    confidence: number;
    classification: string;
    reasoning: string;
    suggestedActions: string[];
    questionsForAnalyst: string[];
  };
  mitigations: {
    firewallRules: string[];
    dnsBlocks: string[];
    siemQueries: string[];
    k8sNetworkPolicies?: string[];
  };
  timestamp: string;
}

// ============================================================================
// COMPONENTS
// ============================================================================

const RiskMeter: React.FC<{ score: number; confidence: number }> = ({ score, confidence }) => {
  const getColor = (score: number) => {
    if (score < 25) return '#10b981'; // green
    if (score < 50) return '#f59e0b'; // yellow
    if (score < 75) return '#f97316'; // orange
    return '#ef4444'; // red
  };

  const getLabel = (score: number) => {
    if (score < 25) return 'LOW RISK';
    if (score < 50) return 'MODERATE';
    if (score < 75) return 'ELEVATED';
    return 'CRITICAL';
  };

  return (
    <div style={{
      background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
      borderRadius: '16px',
      padding: '24px',
      border: '1px solid rgba(255,255,255,0.1)',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <span style={{ color: '#94a3b8', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '1px' }}>
          Threat Assessment
        </span>
        <span style={{ color: '#64748b', fontSize: '11px' }}>
          {confidence}% confidence
        </span>
      </div>
      
      <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '16px' }}>
        <span style={{ 
          fontSize: '48px', 
          fontWeight: '700', 
          fontFamily: 'JetBrains Mono, monospace',
          color: getColor(score),
          textShadow: `0 0 30px ${getColor(score)}40`
        }}>
          {score}
        </span>
        <span style={{ color: '#64748b', fontSize: '18px' }}>/100</span>
      </div>
      
      <div style={{ 
        background: '#0f172a', 
        borderRadius: '8px', 
        height: '8px', 
        overflow: 'hidden',
        marginBottom: '12px'
      }}>
        <div style={{
          width: `${score}%`,
          height: '100%',
          background: `linear-gradient(90deg, ${getColor(score)}80, ${getColor(score)})`,
          borderRadius: '8px',
          transition: 'width 0.5s ease-out'
        }} />
      </div>
      
      <div style={{
        display: 'inline-block',
        padding: '4px 12px',
        background: `${getColor(score)}20`,
        borderRadius: '4px',
        color: getColor(score),
        fontSize: '12px',
        fontWeight: '600',
        letterSpacing: '1px'
      }}>
        {getLabel(score)}
      </div>
    </div>
  );
};

const EnrichmentCard: React.FC<{ title: string; data: any; icon: string }> = ({ title, data, icon }) => {
  if (!data) return null;
  
  return (
    <div style={{
      background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
      borderRadius: '12px',
      padding: '20px',
      border: '1px solid rgba(255,255,255,0.1)',
    }}>
      <div style={{ 
        display: 'flex', 
        alignItems: 'center', 
        gap: '8px', 
        marginBottom: '16px',
        paddingBottom: '12px',
        borderBottom: '1px solid rgba(255,255,255,0.05)'
      }}>
        <span style={{ fontSize: '18px' }}>{icon}</span>
        <span style={{ 
          color: '#e2e8f0', 
          fontSize: '14px', 
          fontWeight: '600',
          textTransform: 'uppercase',
          letterSpacing: '0.5px'
        }}>
          {title}
        </span>
      </div>
      
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {Object.entries(data).map(([key, value]) => (
          <div key={key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ color: '#64748b', fontSize: '12px', textTransform: 'capitalize' }}>
              {key.replace(/([A-Z])/g, ' $1').trim()}
            </span>
            <span style={{ 
              color: '#e2e8f0', 
              fontSize: '13px',
              fontFamily: 'JetBrains Mono, monospace',
              maxWidth: '60%',
              textAlign: 'right',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap'
            }}>
              {typeof value === 'boolean' ? (value ? '✓' : '✗') : 
               Array.isArray(value) ? value.slice(0, 3).join(', ') + (value.length > 3 ? '...' : '') :
               String(value)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

const MitigationPanel: React.FC<{ mitigations: AnalysisResult['mitigations'] }> = ({ mitigations }) => {
  const [activeTab, setActiveTab] = useState<'firewall' | 'dns' | 'siem' | 'k8s'>('siem');
  
  const tabs = [
    { id: 'siem', label: 'SIEM Queries', icon: '🔍', data: mitigations.siemQueries },
    { id: 'firewall', label: 'Firewall', icon: '🛡️', data: mitigations.firewallRules },
    { id: 'dns', label: 'DNS Blocks', icon: '🌐', data: mitigations.dnsBlocks },
    { id: 'k8s', label: 'K8s Policies', icon: '☸️', data: mitigations.k8sNetworkPolicies },
  ].filter(tab => tab.data && tab.data.length > 0);
  
  const activeData = tabs.find(t => t.id === activeTab)?.data || [];
  
  return (
    <div style={{
      background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
      borderRadius: '16px',
      border: '1px solid rgba(255,255,255,0.1)',
      overflow: 'hidden'
    }}>
      <div style={{ 
        display: 'flex', 
        borderBottom: '1px solid rgba(255,255,255,0.1)',
        background: 'rgba(0,0,0,0.2)'
      }}>
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            style={{
              flex: 1,
              padding: '16px',
              background: activeTab === tab.id ? 'rgba(99, 102, 241, 0.2)' : 'transparent',
              border: 'none',
              color: activeTab === tab.id ? '#818cf8' : '#64748b',
              cursor: 'pointer',
              fontSize: '12px',
              fontWeight: '600',
              textTransform: 'uppercase',
              letterSpacing: '0.5px',
              transition: 'all 0.2s',
              borderBottom: activeTab === tab.id ? '2px solid #818cf8' : '2px solid transparent'
            }}
          >
            <span style={{ marginRight: '6px' }}>{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>
      
      <div style={{ padding: '20px' }}>
        <pre style={{
          background: '#0f172a',
          padding: '16px',
          borderRadius: '8px',
          overflow: 'auto',
          maxHeight: '300px',
          fontSize: '12px',
          fontFamily: 'JetBrains Mono, monospace',
          color: '#a5f3fc',
          margin: 0,
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-all'
        }}>
          {activeData.join('\n')}
        </pre>
        
        <button style={{
          marginTop: '12px',
          padding: '10px 20px',
          background: 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)',
          border: 'none',
          borderRadius: '8px',
          color: 'white',
          fontSize: '12px',
          fontWeight: '600',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}
        onClick={() => {
          navigator.clipboard.writeText(activeData.join('\n'));
        }}
        >
          📋 Copy to Clipboard
        </button>
      </div>
    </div>
  );
};

const AnalystGuidance: React.FC<{ analysis: AnalysisResult['llmAnalysis'] }> = ({ analysis }) => {
  return (
    <div style={{
      background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
      borderRadius: '16px',
      padding: '24px',
      border: '1px solid rgba(255,255,255,0.1)',
    }}>
      <h3 style={{ 
        color: '#e2e8f0', 
        fontSize: '14px', 
        fontWeight: '600', 
        marginBottom: '16px',
        textTransform: 'uppercase',
        letterSpacing: '1px',
        display: 'flex',
        alignItems: 'center',
        gap: '8px'
      }}>
        <span style={{ fontSize: '18px' }}>🤖</span> AI Analysis
      </h3>
      
      <p style={{ 
        color: '#cbd5e1', 
        fontSize: '14px', 
        lineHeight: '1.7',
        marginBottom: '20px',
        padding: '16px',
        background: 'rgba(99, 102, 241, 0.1)',
        borderRadius: '8px',
        borderLeft: '3px solid #6366f1'
      }}>
        {analysis.summary}
      </p>
      
      {analysis.reasoning && (
        <div style={{ marginBottom: '20px' }}>
          <h4 style={{ color: '#94a3b8', fontSize: '11px', textTransform: 'uppercase', marginBottom: '8px' }}>
            Reasoning
          </h4>
          <p style={{ color: '#94a3b8', fontSize: '13px', lineHeight: '1.6' }}>
            {analysis.reasoning}
          </p>
        </div>
      )}
      
      {analysis.suggestedActions.length > 0 && (
        <div style={{ marginBottom: '20px' }}>
          <h4 style={{ color: '#94a3b8', fontSize: '11px', textTransform: 'uppercase', marginBottom: '12px' }}>
            Recommended Actions
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {analysis.suggestedActions.map((action, i) => (
              <div key={i} style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '12px',
                padding: '12px',
                background: 'rgba(16, 185, 129, 0.1)',
                borderRadius: '8px'
              }}>
                <span style={{ 
                  color: '#10b981', 
                  fontWeight: '700',
                  fontSize: '12px',
                  minWidth: '20px'
                }}>
                  {i + 1}.
                </span>
                <span style={{ color: '#a7f3d0', fontSize: '13px' }}>{action}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      
      {analysis.questionsForAnalyst.length > 0 && (
        <div>
          <h4 style={{ color: '#94a3b8', fontSize: '11px', textTransform: 'uppercase', marginBottom: '12px' }}>
            Questions for Investigation
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {analysis.questionsForAnalyst.map((q, i) => (
              <div key={i} style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '12px',
                padding: '12px',
                background: 'rgba(251, 191, 36, 0.1)',
                borderRadius: '8px'
              }}>
                <span style={{ color: '#fbbf24', fontSize: '14px' }}>?</span>
                <span style={{ color: '#fde68a', fontSize: '13px' }}>{q}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// ============================================================================
// MAIN APP
// ============================================================================

// Configuration - set these based on your deployment
const API_BASE_URL = import.meta.env?.VITE_API_URL || 'https://sentinel.laurence-avent.workers.dev';
const API_KEY = import.meta.env?.VITE_API_KEY || '';
const GITHUB_REPO = 'https://github.com/postrv/sentinel';

export default function SentinelDashboard() {
  const [indicator, setIndicator] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [apiStatus, setApiStatus] = useState<'checking' | 'online' | 'offline'>('checking');

  // Check API health on mount
  React.useEffect(() => {
    const checkHealth = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/health`);
        setApiStatus(response.ok ? 'online' : 'offline');
      } catch {
        setApiStatus('offline');
      }
    };
    checkHealth();
  }, []);

  const handleAnalyze = useCallback(async () => {
    if (!indicator.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };

      if (API_KEY) {
        headers['X-API-Key'] = API_KEY;
      }

      const response = await fetch(`${API_BASE_URL}/api/analyze`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ indicator: indicator.trim() }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `API error: ${response.status}`);
      }

      const data: AnalysisResult = await response.json();
      setResult(data);
    } catch (err) {
      console.error('Analysis error:', err);
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setLoading(false);
    }
  }, [indicator]);

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(180deg, #0f0f1a 0%, #1a1a2e 50%, #0f172a 100%)',
      fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
      color: '#e2e8f0'
    }}>
      {/* Header */}
      <header style={{
        padding: '24px 48px',
        borderBottom: '1px solid rgba(255,255,255,0.05)',
        background: 'rgba(0,0,0,0.3)',
        backdropFilter: 'blur(10px)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div style={{
              width: '40px',
              height: '40px',
              background: 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)',
              borderRadius: '10px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '20px',
              boxShadow: '0 0 30px rgba(99, 102, 241, 0.3)'
            }}>
              🛡️
            </div>
            <div>
              <h1 style={{ 
                margin: 0, 
                fontSize: '24px', 
                fontWeight: '700',
                background: 'linear-gradient(135deg, #e2e8f0 0%, #94a3b8 100%)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent'
              }}>
                SENTINEL
              </h1>
              <p style={{ margin: 0, fontSize: '11px', color: '#64748b', letterSpacing: '2px', textTransform: 'uppercase' }}>
                AI Security Investigation Platform
              </p>
            </div>
          </div>
          
          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
            <a
              href={GITHUB_REPO}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                padding: '8px 16px',
                background: 'rgba(255, 255, 255, 0.05)',
                borderRadius: '8px',
                fontSize: '12px',
                color: '#94a3b8',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                textDecoration: 'none',
                transition: 'all 0.2s'
              }}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
              </svg>
              GitHub
            </a>
            <div style={{
              padding: '8px 16px',
              background: apiStatus === 'online' ? 'rgba(16, 185, 129, 0.1)' :
                         apiStatus === 'offline' ? 'rgba(239, 68, 68, 0.1)' :
                         'rgba(251, 191, 36, 0.1)',
              borderRadius: '8px',
              fontSize: '12px',
              color: apiStatus === 'online' ? '#10b981' :
                     apiStatus === 'offline' ? '#ef4444' :
                     '#fbbf24',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}>
              <span style={{
                width: '6px',
                height: '6px',
                background: apiStatus === 'online' ? '#10b981' :
                           apiStatus === 'offline' ? '#ef4444' :
                           '#fbbf24',
                borderRadius: '50%'
              }} />
              {apiStatus === 'online' ? 'API Online' :
               apiStatus === 'offline' ? 'API Offline' :
               'Checking...'}
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main style={{ padding: '48px', maxWidth: '1400px', margin: '0 auto' }}>
        {/* Search Section */}
        <div style={{
          background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
          borderRadius: '20px',
          padding: '32px',
          marginBottom: '32px',
          border: '1px solid rgba(255,255,255,0.1)',
          boxShadow: '0 20px 60px rgba(0,0,0,0.3)'
        }}>
          <div style={{ marginBottom: '20px' }}>
            <h2 style={{ 
              margin: 0, 
              fontSize: '16px', 
              fontWeight: '600',
              color: '#94a3b8',
              textTransform: 'uppercase',
              letterSpacing: '1px'
            }}>
              Analyze Indicator
            </h2>
            <p style={{ margin: '8px 0 0', fontSize: '13px', color: '#64748b' }}>
              Enter an IP address, domain, URL, or file hash for comprehensive threat analysis
            </p>
          </div>
          
          <div style={{ display: 'flex', gap: '12px' }}>
            <input
              type="text"
              value={indicator}
              onChange={(e) => setIndicator(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAnalyze()}
              placeholder="192.168.1.1, evil.com, https://phish.site/login, or SHA256..."
              style={{
                flex: 1,
                padding: '16px 20px',
                background: '#0f172a',
                border: '2px solid rgba(99, 102, 241, 0.3)',
                borderRadius: '12px',
                color: '#e2e8f0',
                fontSize: '15px',
                fontFamily: 'JetBrains Mono, monospace',
                outline: 'none',
                transition: 'all 0.2s'
              }}
            />
            <button
              onClick={handleAnalyze}
              disabled={loading || !indicator.trim()}
              style={{
                padding: '16px 32px',
                background: loading ? '#374151' : 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)',
                border: 'none',
                borderRadius: '12px',
                color: 'white',
                fontSize: '14px',
                fontWeight: '600',
                cursor: loading ? 'wait' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                transition: 'all 0.2s',
                boxShadow: loading ? 'none' : '0 10px 30px rgba(99, 102, 241, 0.3)'
              }}
            >
              {loading ? (
                <>
                  <span style={{ 
                    width: '16px', 
                    height: '16px', 
                    border: '2px solid rgba(255,255,255,0.3)',
                    borderTopColor: 'white',
                    borderRadius: '50%',
                    animation: 'spin 1s linear infinite'
                  }} />
                  Analyzing...
                </>
              ) : (
                <>
                  🔍 Analyze
                </>
              )}
            </button>
          </div>
          
          {/* Quick examples */}
          <div style={{ marginTop: '16px', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            <span style={{ color: '#64748b', fontSize: '12px' }}>Try:</span>
            {['8.8.8.8', 'google.com', 'xn--80ak6aa92e.com', '44d88612fea8a8f36de82e1278abb02f'].map(ex => (
              <button
                key={ex}
                onClick={() => setIndicator(ex)}
                style={{
                  padding: '4px 10px',
                  background: 'rgba(99, 102, 241, 0.1)',
                  border: '1px solid rgba(99, 102, 241, 0.2)',
                  borderRadius: '6px',
                  color: '#818cf8',
                  fontSize: '11px',
                  cursor: 'pointer',
                  fontFamily: 'JetBrains Mono, monospace'
                }}
              >
                {ex}
              </button>
            ))}
          </div>
        </div>

        {/* Error Display */}
        {error && (
          <div style={{
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: '12px',
            padding: '16px 20px',
            marginBottom: '32px',
            color: '#fca5a5',
            fontSize: '14px',
            display: 'flex',
            alignItems: 'center',
            gap: '12px'
          }}>
            <span>⚠️</span> {error}
          </div>
        )}

        {/* Results */}
        {result && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            {/* Top Row: Risk + Classification */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '24px' }}>
              <RiskMeter 
                score={result.llmAnalysis.riskScore} 
                confidence={result.llmAnalysis.confidence} 
              />
              
              <div style={{
                background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
                borderRadius: '16px',
                padding: '24px',
                border: '1px solid rgba(255,255,255,0.1)',
              }}>
                <div style={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  gap: '16px',
                  marginBottom: '20px'
                }}>
                  <div style={{
                    padding: '8px 16px',
                    background: result.llmAnalysis.classification === 'malicious' ? 'rgba(239, 68, 68, 0.2)' :
                               result.llmAnalysis.classification === 'suspicious' ? 'rgba(251, 191, 36, 0.2)' :
                               'rgba(16, 185, 129, 0.2)',
                    borderRadius: '8px',
                    color: result.llmAnalysis.classification === 'malicious' ? '#fca5a5' :
                           result.llmAnalysis.classification === 'suspicious' ? '#fde68a' :
                           '#a7f3d0',
                    fontSize: '12px',
                    fontWeight: '700',
                    textTransform: 'uppercase',
                    letterSpacing: '1px'
                  }}>
                    {result.llmAnalysis.classification}
                  </div>
                  <span style={{ 
                    color: '#64748b', 
                    fontSize: '12px',
                    fontFamily: 'JetBrains Mono, monospace'
                  }}>
                    {result.type.toUpperCase()} • Analyzed {new Date(result.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                
                <div style={{
                  fontFamily: 'JetBrains Mono, monospace',
                  fontSize: '18px',
                  color: '#e2e8f0',
                  padding: '16px',
                  background: '#0f172a',
                  borderRadius: '8px',
                  wordBreak: 'break-all'
                }}>
                  {result.indicator}
                </div>
              </div>
            </div>

            {/* Enrichment Row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
              <EnrichmentCard 
                title="VirusTotal" 
                icon="🦠" 
                data={result.enrichment.virustotal ? {
                  'Malicious': result.enrichment.virustotal.malicious,
                  'Suspicious': result.enrichment.virustotal.suspicious,
                  'Clean': result.enrichment.virustotal.harmless,
                  'Reputation': result.enrichment.virustotal.reputation
                } : null} 
              />
              <EnrichmentCard 
                title="AbuseIPDB" 
                icon="🚨" 
                data={result.enrichment.abuseipdb ? {
                  'Abuse Score': `${result.enrichment.abuseipdb.abuseConfidenceScore}%`,
                  'Reports': result.enrichment.abuseipdb.totalReports,
                  'ISP': result.enrichment.abuseipdb.isp,
                  'Country': result.enrichment.abuseipdb.countryCode
                } : null} 
              />
              <EnrichmentCard 
                title="DNS Records" 
                icon="🌐" 
                data={result.enrichment.dns ? {
                  'A Records': result.enrichment.dns.a?.length || 0,
                  'MX Records': result.enrichment.dns.mx?.length || 0,
                  'NS Records': result.enrichment.dns.ns?.length || 0
                } : null} 
              />
            </div>

            {/* AI Analysis */}
            <AnalystGuidance analysis={result.llmAnalysis} />

            {/* Mitigations */}
            <MitigationPanel mitigations={result.mitigations} />
          </div>
        )}

        {/* Empty State */}
        {!result && !loading && (
          <div style={{
            textAlign: 'center',
            padding: '80px 40px',
            color: '#64748b'
          }}>
            <div style={{ 
              fontSize: '64px', 
              marginBottom: '24px',
              opacity: 0.5
            }}>
              🔐
            </div>
            <h3 style={{ 
              color: '#94a3b8', 
              fontSize: '18px', 
              fontWeight: '500',
              marginBottom: '12px'
            }}>
              Ready to Investigate
            </h3>
            <p style={{ fontSize: '14px', maxWidth: '400px', margin: '0 auto' }}>
              Enter an indicator above to begin AI-powered security analysis with threat intelligence enrichment
            </p>
          </div>
        )}
      </main>

      {/* Keyframe animation for spinner */}
      <style>{`
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
      `}</style>
    </div>
  );
}
