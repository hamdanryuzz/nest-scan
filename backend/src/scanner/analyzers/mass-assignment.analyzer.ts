import { BaseAnalyzer } from './base.analyzer';
import { Finding } from '../models/report.model';
import * as fs from 'fs';

export class MassAssignmentAnalyzer extends BaseAnalyzer {
  readonly name = 'mass-assignment';
  readonly description = 'Detects mass assignment vulnerabilities';

  async analyze(projectPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const srcPath = projectPath + '/src';

    for (const file of this.findFiles(srcPath, '.service.ts')) {
      const content = fs.readFileSync(file, 'utf-8');
      for (const { lineNum, text } of this.readLines(content)) {
        const m = text.match(/data\s*:\s*\{?\s*\.\.\.(\w*(?:body|dto|input|payload)\w*)/i);
        if (m) {
          findings.push(this.createFinding('warning', 'Mass Assignment — body di-spread ke Prisma',
            `${m[1]} di-spread langsung ke Prisma. Hacker bisa inject field: status, role, isAdmin.`,
            file, projectPath, { line: lineNum, code: text.trim(),
              suggestion: 'Gunakan field explicit: data: { name: body.name }' }));
        }
      }
    }

    for (const file of this.findFiles(srcPath, '.controller.ts')) {
      const content = fs.readFileSync(file, 'utf-8');
      for (const { lineNum, text } of this.readLines(content)) {
        if (/@Body\(\)\s+\w+\s*:\s*any/.test(text)) {
          findings.push(this.createFinding('critical', '@Body() tipe any — tanpa validasi',
            'Request body TIDAK divalidasi. Hacker bisa kirim field apapun.',
            file, projectPath, { line: lineNum, code: text.trim(),
              suggestion: 'Buat DTO class dengan class-validator decorators.' }));
        }
      }
    }
    return findings;
  }
}
