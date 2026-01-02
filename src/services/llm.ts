/**
 * LLM Analysis Service
 *
 * Handles Claude API integration for security analysis.
 */

import type {
  LLMAnalysis,
  EnrichmentData,
  ParsedIP,
  DomainStructure,
  URLAnalysis,
  HashAnalysis,
  IndicatorType,
} from '../types';

const CLAUDE_MODEL = 'claude-sonnet-4-20250514';
const MAX_TOKENS = 2048;

const SYSTEM_PROMPT = `You are a senior security analyst performing threat intelligence analysis.
Your task is to analyze security indicators and provide actionable intelligence.

IMPORTANT INSTRUCTIONS:
1. Provide analysis in a structured JSON format
2. Be decisive - give clear risk scores and classifications
3. Don't hedge excessively - make a call based on available evidence
4. Focus on actionable insights and next steps
5. Consider context: a private IP is not "malicious" but may indicate issues if found in wrong context

Your response MUST be valid JSON matching this schema:
{
  "summary": "2-3 sentence executive summary",
  "riskScore": 0-100,
  "confidence": 0-100,
  "classification": "benign|suspicious|malicious|unknown",
  "reasoning": "Brief explanation of your analysis",
  "suggestedActions": ["action1", "action2", ...],
  "questionsForAnalyst": ["question1", "question2", ...]
}`;

/**
 * Build prompt with semantic context and enrichment data
 */
function buildLLMPrompt(
  _indicator: string,
  _type: IndicatorType,
  parsed: ParsedIP | DomainStructure | URLAnalysis | HashAnalysis,
  enrichment: EnrichmentData
): string {
  let prompt = `Analyze this security indicator and provide a threat assessment.

`;

  // Add the semantic context
  prompt += parsed.semanticContext;

  prompt += `

=== THREAT INTELLIGENCE ENRICHMENT ===
`;

  // Add enrichment data
  if (enrichment.virustotal) {
    prompt += `
VIRUSTOTAL:
- Malicious detections: ${enrichment.virustotal.malicious}
- Suspicious detections: ${enrichment.virustotal.suspicious}
- Harmless/Clean: ${enrichment.virustotal.harmless}
- Reputation score: ${enrichment.virustotal.reputation}
- Tags: ${enrichment.virustotal.tags.join(', ') || 'None'}
`;
  }

  if (enrichment.abuseipdb) {
    prompt += `
ABUSEIPDB:
- Abuse confidence: ${enrichment.abuseipdb.abuseConfidenceScore}%
- Total reports: ${enrichment.abuseipdb.totalReports}
- Last reported: ${enrichment.abuseipdb.lastReportedAt || 'Never'}
- Usage type: ${enrichment.abuseipdb.usageType}
- ISP: ${enrichment.abuseipdb.isp}
- Whitelisted: ${enrichment.abuseipdb.isWhitelisted ? 'Yes' : 'No'}
`;
  }

  if (enrichment.greynoise) {
    prompt += `
GREYNOISE:
- Seen in scans: ${enrichment.greynoise.seen ? 'Yes' : 'No'}
- Classification: ${enrichment.greynoise.classification}
- Internet noise: ${enrichment.greynoise.noise ? 'Yes' : 'No'}
- RIOT (benign service): ${enrichment.greynoise.riot ? 'Yes' : 'No'}
`;
  }

  if (enrichment.shodan) {
    prompt += `
SHODAN:
- Open ports: ${enrichment.shodan.ports.join(', ') || 'None found'}
- Vulnerabilities: ${enrichment.shodan.vulns.join(', ') || 'None identified'}
- Organization: ${enrichment.shodan.org}
- ASN: ${enrichment.shodan.asn}
`;
  }

  if (enrichment.dns) {
    prompt += `
DNS RECORDS:
- A records: ${enrichment.dns.a.join(', ') || 'None'}
- MX records: ${enrichment.dns.mx.join(', ') || 'None'}
- NS records: ${enrichment.dns.ns.join(', ') || 'None'}
`;
  }

  prompt += `
=== END ENRICHMENT ===

Based on all available information, provide your threat assessment as JSON.`;

  return prompt;
}

/**
 * Perform LLM analysis using Claude
 */
export async function performLLMAnalysis(
  indicator: string,
  type: IndicatorType,
  parsed: ParsedIP | DomainStructure | URLAnalysis | HashAnalysis,
  enrichment: EnrichmentData,
  apiKey: string
): Promise<LLMAnalysis> {
  const prompt = buildLLMPrompt(indicator, type, parsed, enrichment);

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: CLAUDE_MODEL,
        max_tokens: MAX_TOKENS,
        messages: [
          {
            role: 'user',
            content: prompt,
          },
        ],
        system: SYSTEM_PROMPT,
      }),
    });

    if (!response.ok) {
      throw new Error(`Anthropic API error: ${response.status}`);
    }

    const data = (await response.json()) as {
      content?: Array<{ text?: string }>;
    };

    const content = data.content?.[0]?.text || '{}';

    // Parse the JSON response (handle markdown code blocks)
    const analysisText = content.replace(/```json\n?|\n?```/g, '').trim();
    const analysis = JSON.parse(analysisText) as Partial<LLMAnalysis>;

    return {
      summary: analysis.summary || 'Analysis unavailable',
      riskScore: analysis.riskScore || 0,
      confidence: analysis.confidence || 0,
      classification: analysis.classification || 'unknown',
      reasoning: analysis.reasoning || '',
      suggestedActions: analysis.suggestedActions || [],
      questionsForAnalyst: analysis.questionsForAnalyst || [],
    };
  } catch (error) {
    console.error('LLM analysis failed:', error);

    return {
      summary: 'Automated analysis failed. Manual review required.',
      riskScore: 50,
      confidence: 0,
      classification: 'unknown',
      reasoning: `Analysis error: ${error instanceof Error ? error.message : String(error)}`,
      suggestedActions: ['Perform manual analysis'],
      questionsForAnalyst: ['What is the source of this indicator?'],
    };
  }
}

/**
 * Fallback analysis without LLM (when API is unavailable)
 */
export function performLocalAnalysis(
  _indicator: string,
  _type: IndicatorType,
  _parsed: ParsedIP | DomainStructure | URLAnalysis | HashAnalysis,
  enrichment: EnrichmentData
): LLMAnalysis {
  let riskScore = 0;
  const suggestedActions: string[] = [];
  const reasoning: string[] = [];

  // Calculate risk based on enrichment data
  if (enrichment.virustotal) {
    const vt = enrichment.virustotal;
    if (vt.malicious > 0) {
      riskScore += Math.min(vt.malicious * 5, 50);
      reasoning.push(`VirusTotal: ${vt.malicious} malicious detections`);
      suggestedActions.push('Block at firewall', 'Search SIEM logs');
    }
    if (vt.suspicious > 0) {
      riskScore += Math.min(vt.suspicious * 2, 20);
      reasoning.push(`VirusTotal: ${vt.suspicious} suspicious detections`);
    }
  }

  if (enrichment.abuseipdb) {
    const abuse = enrichment.abuseipdb;
    if (abuse.abuseConfidenceScore > 50) {
      riskScore += Math.min(abuse.abuseConfidenceScore / 2, 40);
      reasoning.push(`AbuseIPDB: ${abuse.abuseConfidenceScore}% abuse confidence`);
      suggestedActions.push('Review abuse reports');
    }
  }

  if (enrichment.greynoise) {
    const gn = enrichment.greynoise;
    if (gn.classification === 'malicious') {
      riskScore += 30;
      reasoning.push('GreyNoise: classified as malicious');
    } else if (gn.riot) {
      riskScore -= 20; // Known benign service
      reasoning.push('GreyNoise: known benign service (RIOT)');
    }
  }

  if (enrichment.shodan?.vulns && enrichment.shodan.vulns.length > 0) {
    riskScore += Math.min(enrichment.shodan.vulns.length * 10, 30);
    reasoning.push(`Shodan: ${enrichment.shodan.vulns.length} known vulnerabilities`);
  }

  // Clamp score
  riskScore = Math.max(0, Math.min(100, riskScore));

  // Determine classification
  let classification: string;
  if (riskScore >= 70) {
    classification = 'malicious';
  } else if (riskScore >= 40) {
    classification = 'suspicious';
  } else if (riskScore >= 10) {
    classification = 'unknown';
  } else {
    classification = 'benign';
  }

  return {
    summary: reasoning.length > 0
      ? `Analysis based on threat intelligence. ${reasoning.join('. ')}.`
      : 'No significant threat indicators found.',
    riskScore,
    confidence: enrichment.virustotal ? 70 : 30,
    classification,
    reasoning: reasoning.join('; ') || 'No threat indicators detected',
    suggestedActions: suggestedActions.length > 0 ? suggestedActions : ['Continue monitoring'],
    questionsForAnalyst: ['Is this indicator associated with any known incidents?'],
  };
}
