import { BaseAnalyzer } from './base.analyzer';
import { Finding } from '../models/report.model';
import * as fs from 'fs';
import * as path from 'path';

// Controllers whose @Controller() path or filename match these patterns
// are intentionally public — skip guard check for them.
const PUBLIC_CONTROLLER_PATTERNS = [
  /auth/i, /login/i, /register/i, /public/i,
  /health/i, /status/i, /ping/i, /webhook/i,
];

export class AuthGuardAnalyzer extends BaseAnalyzer {
  readonly name = 'auth-guard';
  readonly description = 'Checks for missing authentication guards';

  async analyze(projectPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const controllers = this.findFiles(projectPath + '/src', '.controller.ts');

    for (const file of controllers) {
      const content = fs.readFileSync(file, 'utf-8');
      if (file.includes('.spec.')) continue;

      // Skip controllers that are explicitly opt-out via @Public() or @SkipAuth()
      if (/@Public\(\)|@SkipAuth\(\)/.test(content)) continue;

      // Extract @Controller('path') value
      const controllerPath = (content.match(/@Controller\(['"](.*?)['"]/)?.[1] ?? '');
      const fileName = path.basename(file);

      // Skip if the controller path or filename looks intentionally public
      const isPublicController = PUBLIC_CONTROLLER_PATTERNS.some(
        p => p.test(controllerPath) || p.test(fileName),
      );
      if (isPublicController) continue;

      const hasClassGuard = this.hasClassDecorator(content, 'UseGuards');
      const httpMethods = this.findPattern(content, /@(Get|Post|Patch|Put|Delete)\(/);

      if (httpMethods.length > 0 && !hasClassGuard) {
        const methodGuards = this.findPattern(content, /@UseGuards\(/);

        // Only flag if NONE of the endpoints have a guard
        if (methodGuards.length === 0) {
          findings.push(this.createFinding('critical', 'Controller tanpa Auth Guard',
            `Controller punya ${httpMethods.length} endpoint tapi tidak ada @UseGuards(). ` +
            `Jika endpoint memang public, tambahkan @Public() / @SkipAuth() untuk suppress warning ini.`,
            file, projectPath,
            { suggestion: 'Tambahkan @UseGuards(JwtAuthGuard) di level class, atau @Public() untuk endpoint yang memang public.' }));
        } else if (methodGuards.length < httpMethods.length) {
          // Some but not all endpoints are guarded — lower severity
          findings.push(this.createFinding('warning',
            `${httpMethods.length - methodGuards.length} endpoint mungkin tanpa guard`,
            `Dari ${httpMethods.length} endpoint, hanya ${methodGuards.length} yang punya @UseGuards(). ` +
            `Pastikan endpoint yang tidak ada guard-nya memang sengaja public.`,
            file, projectPath));
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
