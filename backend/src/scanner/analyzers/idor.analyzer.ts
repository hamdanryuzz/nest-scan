import { BaseAnalyzer } from './base.analyzer';
import { Finding } from '../models/report.model';
import * as fs from 'fs';

export class IdorAnalyzer extends BaseAnalyzer {
  readonly name = 'idor';
  readonly description = 'Detects potential Insecure Direct Object Reference';

  async analyze(projectPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const services = this.findFiles(projectPath + '/src', '.service.ts');

    for (const file of services) {
      const content = fs.readFileSync(file, 'utf-8');
      const lines = this.readLines(content);

      for (let i = 0; i < lines.length; i++) {
        const m = lines[i].text.match(/async\s+(find\w*|get\w*|update\w*|remove\w*|delete\w*)\s*\(\s*id\s*:\s*string/);
        if (!m) continue;

        const block = lines.slice(i, Math.min(i + 30, lines.length)).map(l => l.text).join('\n');
        const hasPrisma = /prisma\.\w+\.(findFirst|findUnique|update|delete)\s*\(/.test(block);
        const hasOwnership = /req\.user|userId|user\.id|ownerId|createdBy/.test(block);

        if (hasPrisma && !hasOwnership) {
          const where = block.match(/where\s*:\s*\{([^}]+)\}/);
          if (where && /^\s*id[\s,]/.test(where[1]) && !where[1].includes('userId')) {
            findings.push(this.createFinding('warning', `Potensi IDOR di ${m[1]}()`,
              `Method terima ID langsung query DB tanpa cek ownership. User bisa akses data orang lain dengan ganti ID.`,
              file, projectPath, { line: lines[i].lineNum, code: lines[i].text.trim(),
                suggestion: 'Tambahkan filter userId/ownership di where clause.' }));
          }
        }
      }
    }
    return findings;
  }
}
