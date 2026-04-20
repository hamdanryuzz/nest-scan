import { ConfidenceLevel, Finding, Severity } from '../models/report.model';
import * as path from 'path';

export abstract class BaseAnalyzer {
  abstract readonly name: string;
  abstract readonly description: string;
  abstract analyze(projectPath: string): Promise<Finding[]>;

  protected createFinding(severity: Severity, title: string, description: string,
    file: string,
    projectPath: string,
    opts?: {
      line?: number;
      code?: string;
      suggestion?: string;
      confidence?: ConfidenceLevel;
      confidenceScore?: number;
      confidenceReason?: string;
    },
  ): Finding {
    const defaultConfidence = this.defaultConfidenceFor(severity);
    return {
      id: `${this.name}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      analyzer: this.name, severity, title, description,
      file: path.relative(projectPath, file).replace(/\\/g, '/'),
      line: opts?.line, code: opts?.code, suggestion: opts?.suggestion,
      confidence: opts?.confidence || defaultConfidence.level,
      confidenceScore: opts?.confidenceScore ?? defaultConfidence.score,
      confidenceReason: opts?.confidenceReason,
    };
  }

  protected confidence(score: number, reason: string): {
    confidence: ConfidenceLevel;
    confidenceScore: number;
    confidenceReason: string;
  } {
    return {
      confidence: this.confidenceLevel(score),
      confidenceScore: score,
      confidenceReason: reason,
    };
  }

  protected readLines(content: string): { lineNum: number; text: string }[] {
    return content.split('\n').map((text, i) => ({ lineNum: i + 1, text }));
  }

  protected findPattern(content: string, pattern: RegExp): { lineNum: number; match: string; text: string }[] {
    const results: { lineNum: number; match: string; text: string }[] = [];
    for (const { lineNum, text } of this.readLines(content)) {
      const m = text.match(pattern);
      if (m) results.push({ lineNum, match: m[0], text: text.trim() });
    }
    return results;
  }

  protected hasClassDecorator(content: string, decorator: string): boolean {
    return new RegExp(`@${decorator}\\(`).test(content);
  }

  protected findFiles(dir: string, suffix: string): string[] {
    const fs = require('fs');
    const results: string[] = [];
    try {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory() && !['node_modules', 'dist', '.git'].includes(entry.name))
          results.push(...this.findFiles(full, suffix));
        else if (entry.isFile() && entry.name.endsWith(suffix))
          results.push(full);
      }
    } catch {}
    return results;
  }

  private defaultConfidenceFor(severity: Severity): { level: ConfidenceLevel; score: number } {
    if (severity === 'critical') return { level: 'high', score: 90 };
    if (severity === 'warning') return { level: 'medium', score: 72 };
    return { level: 'low', score: 55 };
  }

  private confidenceLevel(score: number): ConfidenceLevel {
    if (score >= 85) return 'high';
    if (score >= 65) return 'medium';
    return 'low';
  }
}
