import { BaseAnalyzer } from './base.analyzer';
import { Finding } from '../models/report.model';
import * as fs from 'fs';

export class AuthGuardAnalyzer extends BaseAnalyzer {
  readonly name = 'auth-guard';
  readonly description = 'Checks for missing authentication guards';

  async analyze(projectPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const controllers = this.findFiles(projectPath + '/src', '.controller.ts');

    for (const file of controllers) {
      const content = fs.readFileSync(file, 'utf-8');
      if (file.includes('.spec.')) continue;

      const hasClassGuard = this.hasClassDecorator(content, 'UseGuards');
      const httpMethods = this.findPattern(content, /@(Get|Post|Patch|Put|Delete)\(/);

      if (httpMethods.length > 0 && !hasClassGuard) {
        const methodGuards = this.findPattern(content, /@UseGuards\(/);
        if (methodGuards.length === 0) {
          findings.push(this.createFinding('critical', 'Controller tanpa Auth Guard',
            `Controller punya ${httpMethods.length} endpoint tapi TIDAK ada @UseGuards(). Semua endpoint bisa diakses tanpa login.`,
            file, projectPath,
            { suggestion: 'Tambahkan @UseGuards(AuthGuard) di level class.' }));
        }
      }

      // Check ensureAuthorized defined but not called
      if (content.includes('ensureAuthorized(') || content.includes('ensureAuthorized (')) {
        const calls = (content.match(/this\.ensureAuthorized\s*\(/g) || []).length;
        if (calls === 0 && httpMethods.length > 0) {
          findings.push(this.createFinding('critical', 'ensureAuthorized() didefinisi tapi TIDAK pernah dipanggil',
            `Ada ${httpMethods.length} endpoint tapi ensureAuthorized() tidak pernah dipanggil. Authorization check tidak jalan.`,
            file, projectPath,
            { suggestion: 'Panggil this.ensureAuthorized(req) di setiap handler.' }));
        } else if (calls > 0 && calls < httpMethods.length) {
          findings.push(this.createFinding('warning',
            `${httpMethods.length - calls} endpoint tidak panggil ensureAuthorized()`,
            `Dari ${httpMethods.length} endpoint, hanya ${calls} yang punya authorization check.`,
            file, projectPath));
        }
      }
    }
    return findings;
  }
}
