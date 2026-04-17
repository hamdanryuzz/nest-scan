import { BaseAnalyzer } from './base.analyzer';
import { Finding } from '../models/report.model';
import * as fs from 'fs';
import * as path from 'path';

export class CodeSmellAnalyzer extends BaseAnalyzer {
  readonly name = 'code-smell';
  readonly description = 'Detects code smells like long files, console.log usage, and duplicate functions';

  async analyze(projectPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const srcPath = path.join(projectPath, 'src');
    if (!fs.existsSync(srcPath)) return findings;

    const tsFiles = this.findFiles(srcPath, '.ts');
    for (const file of tsFiles) {
      if (file.includes('.spec.') || file.includes('.test.')) continue;
      const content = fs.readFileSync(file, 'utf-8');
      this.checkFileLength(content, file, projectPath, findings);
      this.checkConsoleLogs(content, file, projectPath, findings);
      this.checkLongMethods(content, file, projectPath, findings);
      this.checkTodoFixme(content, file, projectPath, findings);
    }

    this.checkDuplicateFunctions(tsFiles, projectPath, findings);
    return findings;
  }

  private checkFileLength(content: string, file: string, projectPath: string, findings: Finding[]): void {
    const lineCount = content.split('\n').length;
    if (lineCount > 500) {
      findings.push(this.createFinding('warning', `File terlalu panjang: ${lineCount} baris`,
        `File ini punya ${lineCount} baris. File yang terlalu panjang sulit di-review dan maintain. Consider split ke beberapa file.`,
        file, projectPath, { suggestion: 'Pecah ke beberapa file/class berdasarkan tanggung jawab.' }));
    } else if (lineCount > 300) {
      findings.push(this.createFinding('info', `File cukup panjang: ${lineCount} baris`,
        'Pertimbangkan untuk memecah file ini jika masih akan bertambah.', file, projectPath));
    }
  }

  private checkConsoleLogs(content: string, file: string, projectPath: string, findings: Finding[]): void {
    const matches = this.findPattern(content, /console\.(log|debug|info)\(/);
    if (matches.length > 0) {
      findings.push(this.createFinding('info', `${matches.length}x console.log di production code`,
        'Gunakan NestJS Logger instead of console.log. Logger bisa diconfig per environment dan punya context.',
        file, projectPath, { line: matches[0].lineNum,
          suggestion: 'Ganti dengan: private readonly logger = new Logger(ClassName.name); this.logger.log(...)' }));
    }
  }

  private checkLongMethods(content: string, file: string, projectPath: string, findings: Finding[]): void {
    // Simple heuristic: find method definitions and count lines until next method or closing brace
    const lines = this.readLines(content);
    let methodStart: { name: string; line: number } | null = null;
    let braceDepth = 0;

    for (const { lineNum, text } of lines) {
      const methodMatch = text.match(/(?:async\s+)?(\w+)\s*\([^)]*\)\s*(?::\s*\w+[<>\[\]|,\s]*)?\s*\{/);
      if (methodMatch && !text.includes('if') && !text.includes('for') && !text.includes('while')) {
        if (methodStart) {
          const length = lineNum - methodStart.line;
          if (length > 60) {
            findings.push(this.createFinding('info',
              `Method ${methodStart.name}() terlalu panjang: ${length} baris`,
              'Method yang panjang sulit di-test dan di-review. Pecah ke helper methods.',
              file, projectPath, { line: methodStart.line }));
          }
        }
        methodStart = { name: methodMatch[1], line: lineNum };
      }
    }
  }

  private checkTodoFixme(content: string, file: string, projectPath: string, findings: Finding[]): void {
    const matches = this.findPattern(content, /\/\/\s*(TODO|FIXME|HACK|XXX|BUG)[\s:]/i);
    for (const m of matches) {
      findings.push(this.createFinding('info', `${m.match} ditemukan`,
        `Ada catatan developer yang belum diselesaikan.`,
        file, projectPath, { line: m.lineNum, code: m.text }));
    }
  }

  private checkDuplicateFunctions(files: string[], projectPath: string, findings: Finding[]): void {
    const functionMap = new Map<string, string[]>();

    for (const file of files) {
      const content = fs.readFileSync(file, 'utf-8');
      const matches = content.matchAll(/(?:private|protected|public)?\s*(?:async\s+)?(\w+)\s*\([^)]*\)\s*(?::\s*\S+)?\s*\{/g);
      for (const m of matches) {
        const name = m[1];
        if (['constructor', 'onModuleInit', 'onModuleDestroy'].includes(name)) continue;
        if (!functionMap.has(name)) functionMap.set(name, []);
        functionMap.get(name)!.push(path.relative(projectPath, file).replace(/\\/g, '/'));
      }
    }

    for (const [name, files] of functionMap) {
      if (files.length > 2 && !['findAll', 'findOne', 'create', 'update', 'remove'].includes(name)) {
        findings.push(this.createFinding('info',
          `Function "${name}" duplikat di ${files.length} file`,
          `Function ini ada di: ${files.slice(0, 5).join(', ')}${files.length > 5 ? '...' : ''}. Consider extract ke shared utility.`,
          files[0], projectPath));
      }
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

