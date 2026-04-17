import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { GoogleGenerativeAI } from '@google/generative-ai';
import { Finding } from '../models/report.model';

export interface AiReview {
  executiveSummary: string;
  prioritizedFindings: AiFinding[];
  overallRiskScore: number;
  overallRiskLevel: string;
}

export interface AiFinding {
  originalId: string;
  aiSeverity: string;
  explanation: string;
  fixCode: string;
  impact: string;
  priority: number;
}

@Injectable()
export class GemmaService {
  private readonly logger = new Logger(GemmaService.name);
  private readonly apiKey: string;

  constructor(private readonly config: ConfigService) {
    this.apiKey = this.config.get<string>('GEMINI_API_KEY') || '';
    if (this.apiKey) {
      this.logger.log('Gemini API key loaded from .env ✓');
    } else {
      this.logger.warn('GEMINI_API_KEY not set — AI review disabled');
    }
  }

  get isEnabled(): boolean {
    return !!this.apiKey;
  }

  async reviewFindings(
    findings: Finding[],
    fileContents: Map<string, string>,
  ): Promise<AiReview> {
    if (!this.apiKey) return this.fallbackReview(findings);

    try {
      const genAI = new GoogleGenerativeAI(this.apiKey);
      const model = genAI.getGenerativeModel({ model: 'gemma-3-27b-it' });

      const findingsContext = findings.slice(0, 20).map((f, i) => {
        let codeSnippet = '';
        if (f.file && fileContents.has(f.file)) {
          const lines = fileContents.get(f.file).split('\n');
          const start = Math.max(0, (f.line || 1) - 5);
          const end = Math.min(lines.length, (f.line || 1) + 10);
          codeSnippet = lines.slice(start, end).map((l, idx) => `${start + idx + 1}: ${l}`).join('\n');
        }
        return `### Finding ${i + 1}: [${f.severity.toUpperCase()}] ${f.title}
File: ${f.file}${f.line ? `:${f.line}` : ''}
Analyzer: ${f.analyzer}
Description: ${f.description}
${codeSnippet ? `Code:\n\`\`\`typescript\n${codeSnippet}\n\`\`\`` : ''}`;
      }).join('\n\n');

      const prompt = `Kamu adalah security engineer senior yang review NestJS codebase.
Berikut adalah hasil static analysis. Untuk setiap finding:
1. Beri penjelasan dampak security/quality dalam bahasa Indonesia yang mudah dipahami QA non-developer
2. Beri contoh kode fix yang bisa langsung di-copy-paste
3. Beri skor prioritas 1-10 (10 = paling urgent)
4. Beri risk score keseluruhan 0-100

${findingsContext}

Respond in JSON format exactly like this:
{
  "executiveSummary": "Ringkasan 2-3 kalimat untuk manager",
  "overallRiskScore": 65,
  "overallRiskLevel": "MEDIUM",
  "prioritizedFindings": [
    {
      "originalId": "finding id",
      "aiSeverity": "HIGH",
      "explanation": "Penjelasan dampak",
      "fixCode": "// Contoh kode fix",
      "impact": "Dampak jika tidak di-fix",
      "priority": 8
    }
  ]
}

IMPORTANT: Return ONLY valid JSON, no markdown wrapping.`;

      this.logger.log('Sending to Gemma AI...');
      const result = await model.generateContent(prompt);
      const text = result.response.text();

      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        this.logger.warn('AI response not valid JSON, using fallback');
        return this.fallbackReview(findings);
      }

      const parsed = JSON.parse(jsonMatch[0]) as AiReview;
      this.logger.log(`AI review done: risk score ${parsed.overallRiskScore}`);
      return parsed;
    } catch (error: any) {
      this.logger.error(`Gemma error: ${error.message}`);
      return this.fallbackReview(findings);
    }
  }

  private fallbackReview(findings: Finding[]): AiReview {
    const c = findings.filter(f => f.severity === 'critical').length;
    const w = findings.filter(f => f.severity === 'warning').length;
    const score = Math.min(100, c * 20 + w * 8);
    return {
      executiveSummary: `Ditemukan ${c} critical dan ${w} warning issues.${!this.apiKey ? ' Tambahkan GEMINI_API_KEY di .env untuk AI review.' : ''}`,
      overallRiskScore: score,
      overallRiskLevel: score >= 70 ? 'CRITICAL' : score >= 40 ? 'HIGH' : score >= 20 ? 'MEDIUM' : 'LOW',
      prioritizedFindings: findings.map(f => ({
        originalId: f.id, aiSeverity: f.severity.toUpperCase(),
        explanation: f.description, fixCode: f.suggestion || '',
        impact: f.severity === 'critical' ? 'High security risk' : 'Code quality issue',
        priority: f.severity === 'critical' ? 9 : f.severity === 'warning' ? 6 : 3,
      })),
    };
  }
}
