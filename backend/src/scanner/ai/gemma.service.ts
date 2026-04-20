import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { GoogleGenerativeAI, GenerativeModel } from '@google/generative-ai';
import {
  AiFinding,
  AiFindingActionResponse,
  AiFindingActionType,
  AiReview,
  AiValidation,
  Finding,
} from '../models/report.model';
import { buildFindingContext } from './ai-context.util';

@Injectable()
export class GemmaService {
  private readonly logger = new Logger(GemmaService.name);
  private readonly apiKey: string;
  private readonly modelName = 'gemma-3-27b-it';

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

  async validateLikelyFalsePositives(
    findings: Finding[],
    fileContents: Map<string, string>,
  ): Promise<Map<string, AiValidation>> {
    if (!this.apiKey) return new Map();

    const candidates = findings.filter(finding => finding.confidence !== 'high');
    if (candidates.length === 0) return new Map();

    try {
      const model = this.getModel();
      const validations = new Map<string, AiValidation>();

      for (const chunk of this.chunk(candidates, 6)) {
        const chunkContext = chunk.map((finding, index) => {
          return `### Candidate ${index + 1}\n${buildFindingContext(finding, fileContents)}`;
        }).join('\n\n');

        const prompt = `Kamu adalah security reviewer senior untuk NestJS.
Tugasmu adalah memvalidasi finding static analysis yang confidence awalnya LOW atau MEDIUM.
Untuk setiap finding, tentukan:
- likely_true_positive
- needs_manual_review
- likely_false_positive

Gunakan konteks kode secara konservatif. Jangan bilang true positive kalau bukti belum cukup.

${chunkContext}

Return JSON persis dengan format:
{
  "validations": [
    {
      "originalId": "finding-id",
      "verdict": "likely_true_positive",
      "rationale": "alasan singkat dan konkret",
      "confidence": 82
    }
  ]
}

IMPORTANT:
- Return ONLY valid JSON.
- confidence harus integer 0-100.
- rationale maksimal 2 kalimat.`;

        const parsed = await this.generateStructured<{ validations?: Array<{
          originalId: string;
          verdict: AiValidation['verdict'];
          rationale: string;
          confidence: number;
        }> }>(model, prompt);

        for (const validation of parsed.validations || []) {
          if (!validation.originalId || !validation.verdict) continue;
          validations.set(validation.originalId, {
            verdict: validation.verdict,
            rationale: validation.rationale || 'AI belum memberi alasan terstruktur.',
            confidence: this.normalizeScore(validation.confidence, 60),
          });
        }
      }

      return validations;
    } catch (error: any) {
      this.logger.error(`Gemma validation error: ${error.message}`);
      return new Map();
    }
  }

  async reviewFindings(
    findings: Finding[],
    fileContents: Map<string, string>,
  ): Promise<AiReview> {
    if (!this.apiKey) return this.fallbackReview(findings);

    try {
      const model = this.getModel();
      const prioritizedFindings: AiFinding[] = [];

      for (const chunk of this.chunk(findings, 6)) {
        const chunkContext = chunk.map((finding, index) => {
          return `### Finding ${index + 1}\n${buildFindingContext(finding, fileContents)}`;
        }).join('\n\n');

        const prompt = `Kamu adalah security engineer senior yang me-review NestJS codebase.
Analisis setiap finding di bawah ini. Fokus pada prioritas engineering, dampak ke bisnis, dan perbaikan yang realistis.

${chunkContext}

Return JSON persis dengan format:
{
  "prioritizedFindings": [
    {
      "originalId": "finding id",
      "aiSeverity": "HIGH",
      "explanation": "penjelasan ringkas dalam bahasa Indonesia",
      "fixCode": "// contoh patch atau snippet fix",
      "impact": "apa akibatnya jika tidak diperbaiki",
      "priority": 8,
      "reviewNotes": "catatan singkat tambahan"
    }
  ]
}

IMPORTANT:
- Return ONLY valid JSON.
- explanation maksimal 4 kalimat.
- priority harus integer 1-10.
- fixCode boleh string kosong kalau fix belum pasti.`;

        const parsed = await this.generateStructured<{ prioritizedFindings?: Array<Partial<AiFinding> & { originalId: string }> }>(model, prompt);
        for (const aiFinding of parsed.prioritizedFindings || []) {
          if (!aiFinding.originalId) continue;
          prioritizedFindings.push({
            originalId: aiFinding.originalId,
            aiSeverity: aiFinding.aiSeverity || 'MEDIUM',
            explanation: aiFinding.explanation || 'AI tidak memberi penjelasan tambahan.',
            fixCode: aiFinding.fixCode || '',
            impact: aiFinding.impact || 'Perlu review manual untuk menilai dampak detail.',
            priority: this.normalizePriority(aiFinding.priority),
            reviewNotes: aiFinding.reviewNotes || '',
          });
        }
      }

      const mergedFindings = this.mergePrioritizedFindings(findings, prioritizedFindings);
      const summary = await this.summarizeReview(model, findings, mergedFindings);

      this.logger.log(`AI review done: ${mergedFindings.length} prioritized findings`);
      return {
        executiveSummary: summary.executiveSummary,
        overallRiskScore: summary.overallRiskScore,
        overallRiskLevel: summary.overallRiskLevel,
        prioritizedFindings: mergedFindings,
      };
    } catch (error: any) {
      this.logger.error(`Gemma review error: ${error.message}`);
      return this.fallbackReview(findings);
    }
  }

  async generateFindingAction(
    reportId: string,
    finding: Finding,
    action: AiFindingActionType,
    fileContents: Map<string, string>,
  ): Promise<AiFindingActionResponse> {
    if (!this.apiKey) {
      throw new Error('GEMINI_API_KEY belum diset. AI action tidak tersedia.');
    }

    try {
      const model = this.getModel();
      const prompt = this.buildActionPrompt(finding, action, fileContents);
      const parsed = await this.generateStructured<{ title?: string; content?: string }>(model, prompt);

      return {
        reportId,
        findingId: finding.id,
        action,
        title: parsed.title || this.defaultActionTitle(action, finding.title),
        content: parsed.content || this.defaultActionContent(action, finding),
        generatedAt: new Date().toISOString(),
      };
    } catch (error: any) {
      this.logger.error(`Gemma finding action error: ${error.message}`);
      return {
        reportId,
        findingId: finding.id,
        action,
        title: this.defaultActionTitle(action, finding.title),
        content: this.defaultActionContent(action, finding),
        generatedAt: new Date().toISOString(),
      };
    }
  }

  private async summarizeReview(
    model: GenerativeModel,
    findings: Finding[],
    prioritizedFindings: AiFinding[],
  ): Promise<Pick<AiReview, 'executiveSummary' | 'overallRiskScore' | 'overallRiskLevel'>> {
    const compactFindings = prioritizedFindings.slice(0, 12).map(aiFinding => {
      const original = findings.find(finding => finding.id === aiFinding.originalId);
      return `- [${original?.severity.toUpperCase() || 'INFO'}] ${original?.title || aiFinding.originalId} | ` +
        `AI severity: ${aiFinding.aiSeverity} | priority: ${aiFinding.priority} | ` +
        `validation: ${original?.aiValidation?.verdict || 'not-run'}`;
    }).join('\n');

    const prompt = `Kamu adalah security lead yang membuat executive summary untuk hasil scan NestJS.
Berikut temuan-temuan yang sudah diprioritaskan:

${compactFindings || '- Tidak ada finding'}

Return JSON persis dengan format:
{
  "executiveSummary": "Ringkasan 2-3 kalimat untuk manager",
  "overallRiskScore": 65,
  "overallRiskLevel": "MEDIUM"
}

IMPORTANT:
- Return ONLY valid JSON.
- overallRiskScore harus integer 0-100.
- overallRiskLevel salah satu dari LOW, MEDIUM, HIGH, CRITICAL.`;

    try {
      const parsed = await this.generateStructured<{
        executiveSummary?: string;
        overallRiskScore?: number;
        overallRiskLevel?: string;
      }>(model, prompt);

      return {
        executiveSummary: parsed.executiveSummary || this.fallbackReview(findings).executiveSummary,
        overallRiskScore: this.normalizeScore(parsed.overallRiskScore, this.fallbackReview(findings).overallRiskScore),
        overallRiskLevel: this.normalizeRiskLevel(parsed.overallRiskLevel, this.fallbackReview(findings).overallRiskLevel),
      };
    } catch {
      const fallback = this.fallbackReview(findings);
      return {
        executiveSummary: fallback.executiveSummary,
        overallRiskScore: fallback.overallRiskScore,
        overallRiskLevel: fallback.overallRiskLevel,
      };
    }
  }

  private buildActionPrompt(
    finding: Finding,
    action: AiFindingActionType,
    fileContents: Map<string, string>,
  ): string {
    const sharedContext = buildFindingContext(finding, fileContents);

    const instructionByAction: Record<AiFindingActionType, string> = {
      explain: 'Jelaskan akar masalah, kenapa rule ini terpanggil, bagian kode mana yang paling relevan, dan langkah review manual berikutnya.',
      'fix-patch': 'Buat patch proposal yang konkret. Sertakan before/after atau snippet pengganti yang realistis untuk NestJS. Jika patch penuh belum aman, bilang apa yang masih perlu dipastikan.',
      'attack-scenario': 'Jelaskan skenario exploit realistis: precondition, langkah serangan, dampak, dan sinyal yang perlu dimonitor. Hindari instruksi ofensif yang terlalu operasional; fokus pada defensive understanding.',
    };

    return `Kamu adalah security engineer senior untuk code review NestJS.
Tugasmu sekarang adalah membantu engineer untuk satu finding secara mendalam.

Action: ${action}
Instruksi spesifik: ${instructionByAction[action]}

${sharedContext}

Return JSON persis dengan format:
{
  "title": "judul singkat hasil AI",
  "content": "isi markdown/plaintext yang rapi untuk engineer"
}

IMPORTANT:
- Return ONLY valid JSON.
- content boleh multi-line.
- Jawab dalam bahasa Indonesia.`;
  }

  private mergePrioritizedFindings(findings: Finding[], aiFindings: AiFinding[]): AiFinding[] {
    const merged = new Map<string, AiFinding>();

    for (const aiFinding of aiFindings) {
      const existing = merged.get(aiFinding.originalId);
      if (!existing || aiFinding.priority > existing.priority) {
        merged.set(aiFinding.originalId, aiFinding);
      }
    }

    for (const finding of findings) {
      if (!merged.has(finding.id)) {
        merged.set(finding.id, {
          originalId: finding.id,
          aiSeverity: finding.severity.toUpperCase(),
          explanation: finding.description,
          fixCode: finding.suggestion || '',
          impact: finding.severity === 'critical' ? 'High security risk' : 'Perlu penilaian engineering lebih lanjut.',
          priority: finding.severity === 'critical' ? 9 : finding.severity === 'warning' ? 6 : 3,
          reviewNotes: finding.aiValidation ? `AI validation: ${finding.aiValidation.verdict}` : '',
        });
      }
    }

    return Array.from(merged.values()).sort((a, b) => b.priority - a.priority);
  }

  private fallbackReview(findings: Finding[]): AiReview {
    const critical = findings.filter(f => f.severity === 'critical').length;
    const warning = findings.filter(f => f.severity === 'warning').length;
    const score = Math.min(100, critical * 20 + warning * 8);

    return {
      executiveSummary: `Ditemukan ${critical} critical dan ${warning} warning issues.${!this.apiKey ? ' Tambahkan GEMINI_API_KEY di .env untuk AI review.' : ''}`,
      overallRiskScore: score,
      overallRiskLevel: score >= 70 ? 'CRITICAL' : score >= 40 ? 'HIGH' : score >= 20 ? 'MEDIUM' : 'LOW',
      prioritizedFindings: findings.map(finding => ({
        originalId: finding.id,
        aiSeverity: finding.severity.toUpperCase(),
        explanation: finding.description,
        fixCode: finding.suggestion || '',
        impact: finding.severity === 'critical' ? 'High security risk' : 'Code quality issue',
        priority: finding.severity === 'critical' ? 9 : finding.severity === 'warning' ? 6 : 3,
        reviewNotes: finding.aiValidation ? `AI validation: ${finding.aiValidation.verdict}` : '',
      })),
    };
  }

  private getModel(): GenerativeModel {
    const genAI = new GoogleGenerativeAI(this.apiKey);
    return genAI.getGenerativeModel({ model: this.modelName });
  }

  private async generateStructured<T>(model: GenerativeModel, prompt: string): Promise<T> {
    const result = await model.generateContent(prompt);
    const text = result.response.text();
    const json = this.extractJson(text);
    return JSON.parse(json) as T;
  }

  private extractJson(text: string): string {
    const match = text.match(/\{[\s\S]*\}/);
    if (!match) {
      throw new Error('AI response is not valid JSON');
    }
    return match[0];
  }

  private chunk<T>(items: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let index = 0; index < items.length; index += size) {
      chunks.push(items.slice(index, index + size));
    }
    return chunks;
  }

  private normalizePriority(value: unknown): number {
    const parsed = typeof value === 'number' ? value : Number(value);
    if (Number.isNaN(parsed)) return 5;
    return Math.max(1, Math.min(10, Math.round(parsed)));
  }

  private normalizeScore(value: unknown, fallback: number): number {
    const parsed = typeof value === 'number' ? value : Number(value);
    if (Number.isNaN(parsed)) return fallback;
    return Math.max(0, Math.min(100, Math.round(parsed)));
  }

  private normalizeRiskLevel(value: unknown, fallback: string): string {
    if (typeof value !== 'string') return fallback;
    const normalized = value.toUpperCase();
    if (['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(normalized)) return normalized;
    return fallback;
  }

  private defaultActionTitle(action: AiFindingActionType, findingTitle: string): string {
    if (action === 'explain') return `AI Explanation - ${findingTitle}`;
    if (action === 'fix-patch') return `AI Fix Patch - ${findingTitle}`;
    return `AI Attack Scenario - ${findingTitle}`;
  }

  private defaultActionContent(action: AiFindingActionType, finding: Finding): string {
    if (action === 'explain') {
      return `${finding.description}\n\nLokasi utama: ${finding.file}${finding.line ? `:${finding.line}` : ''}.`;
    }

    if (action === 'fix-patch') {
      return `Belum ada patch AI yang terstruktur. Gunakan suggestion scanner sebagai titik awal:\n\n${finding.suggestion || 'Perlu review manual.'}`;
    }

    return `Skenario serangan belum tersedia. Mulai dari memahami bagaimana input pada ${finding.file}${finding.line ? `:${finding.line}` : ''} bisa mencapai sink yang dilaporkan.`;
  }
}
