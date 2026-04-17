import { BaseAnalyzer } from './base.analyzer';
import { Finding } from '../models/report.model';
import * as fs from 'fs';
import * as path from 'path';

export class TypeSafetyAnalyzer extends BaseAnalyzer {
  readonly name = 'type-safety';
  readonly description = 'Detects excessive use of `any` type and untyped returns';

  async analyze(projectPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const srcPath = path.join(projectPath, 'src');
    if (!fs.existsSync(srcPath)) return findings;

    const tsFiles = this.findFiles(srcPath, '.ts');
    for (const file of tsFiles) {
      if (file.includes('.spec.') || file.includes('.test.') || file.includes('.dto.')) continue;
      const content = fs.readFileSync(file, 'utf-8');
      this.checkAnyUsage(content, file, projectPath, findings);
      this.checkUntypedReturns(content, file, projectPath, findings);
    }

    return findings;
  }

  private checkAnyUsage(content: string, file: string, projectPath: string, findings: Finding[]): void {
    const anyMatches = this.findPattern(content, /:\s*any\b/);
    const promiseAnyMatches = this.findPattern(content, /Promise<any>/);

    const totalAny = anyMatches.length;
    if (totalAny > 10) {
      findings.push(this.createFinding('warning', `${totalAny}x penggunaan tipe \`any\``,
        `File ini punya ${totalAny} penggunaan tipe \`any\`. Type safety hilang — error tidak terdeteksi saat compile.`,
        file, projectPath, { suggestion: 'Buat interface/type untuk return values dan parameters.' }));
    }

    if (promiseAnyMatches.length > 0) {
      findings.push(this.createFinding('warning', `${promiseAnyMatches.length}x Promise<any> return type`,
        `${promiseAnyMatches.length} method return Promise<any>. Caller tidak tau bentuk datanya — error bisa terjadi tanpa warning.`,
        file, projectPath, { line: promiseAnyMatches[0].lineNum,
          suggestion: 'Definisikan return type: Promise<TagResponse> instead of Promise<any>.' }));
    }
  }

  private checkUntypedReturns(content: string, file: string, projectPath: string, findings: Finding[]): void {
    // Methods that return buildWhere(): any or normalize(): any
    const matches = this.findPattern(content, /(?:private|protected|public)?\s*(?:async\s+)?\w+\([^)]*\)\s*:\s*any/);
    for (const m of matches) {
      findings.push(this.createFinding('info', 'Method return type `any`',
        'Method ini return `any` — kehilangan type checking di caller.',
        file, projectPath, { line: m.lineNum, code: m.text }));
    }
  }

  protected findFiles(dir: string, suffix: string): string[] {
    const results: string[] = [];
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== 'dist')
          results.push(...this.findFiles(full, suffix));
        else if (entry.isFile() && entry.name.endsWith(suffix))
          results.push(full);
      }
    } catch { /* skip */ }
    return results;
  }
}

