import { BaseAnalyzer } from './base.analyzer';
import { Finding } from '../models/report.model';
import * as fs from 'fs';

export class InjectionAnalyzer extends BaseAnalyzer {
  readonly name = 'injection';
  readonly description = 'Detects SQL injection and code injection';

  async analyze(projectPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const tsFiles = this.findFiles(projectPath + '/src', '.ts');

    for (const file of tsFiles) {
      const content = fs.readFileSync(file, 'utf-8');
      const lines = this.readLines(content);

      for (const { lineNum, text } of lines) {
        // Raw SQL with string concat
        if (/\$(?:queryRaw|executeRaw)\s*\(/.test(text)) {
          if (/\+\s*['"`]|['"`]\s*\+/.test(text) || /\$(?:queryRaw|executeRaw)\s*\(\s*`/.test(text)) {
            findings.push(this.createFinding('critical', 'SQL Injection — raw query pakai string concatenation',
              'Prisma raw query tidak di-parameterize. Hacker bisa inject SQL: \' OR 1=1; DROP TABLE users; --',
              file, projectPath, { line: lineNum, code: text.trim(),
                suggestion: 'Gunakan tagged template: prisma.$queryRaw`...${id}` (tanpa parentheses).' }));
          }
        }

        // eval / Function
        if (/\beval\s*\(/.test(text)) {
          findings.push(this.createFinding('critical', 'Code Injection — eval()',
            'eval() memungkinkan eksekusi kode arbitrary dari user input.',
            file, projectPath, { line: lineNum, code: text.trim() }));
        }
        if (/new\s+Function\s*\(/.test(text)) {
          findings.push(this.createFinding('critical', 'Code Injection — new Function()',
            'new Function() sama bahayanya dengan eval().',
            file, projectPath, { line: lineNum, code: text.trim() }));
        }
      }
    }
    return findings;
  }
}
