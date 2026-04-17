import { Finding, Severity } from '../models/report.model';
import * as path from 'path';

export abstract class BaseAnalyzer {
  abstract readonly name: string;
  abstract readonly description: string;
  abstract analyze(projectPath: string): Promise<Finding[]>;

  protected createFinding(severity: Severity, title: string, description: string,
    file: string, projectPath: string, opts?: { line?: number; code?: string; suggestion?: string }): Finding {
    return {
      id: `${this.name}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      analyzer: this.name, severity, title, description,
      file: path.relative(projectPath, file).replace(/\\/g, '/'),
      line: opts?.line, code: opts?.code, suggestion: opts?.suggestion,
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
}
