import { BaseAnalyzer } from './base.analyzer';
import { Finding } from '../models/report.model';
import * as fs from 'fs';
import * as path from 'path';

export class RateLimitAnalyzer extends BaseAnalyzer {
  readonly name = 'rate-limit';
  readonly description = 'Checks auth endpoints for rate limiting';

  private readonly AUTH_PATTERNS = [/login/i, /signin/i, /register/i, /forgot/i, /reset/i, /otp/i];

  async analyze(projectPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const srcPath = path.join(projectPath, 'src');
    if (!fs.existsSync(srcPath)) return findings;

    const controllers = this.findFiles(srcPath, '.controller.ts');
    for (const file of controllers) {
      const content = fs.readFileSync(file, 'utf-8');
      const hasThrottle = content.includes('@Throttle') || content.includes('ThrottlerGuard');
      const lines = this.readLines(content);

      for (const { lineNum, text } of lines) {
        const m = text.match(/@(Post|Get)\s*\(\s*['"`]([^'"`]*)['"`]\)/);
        if (!m) continue;
        if (!this.AUTH_PATTERNS.some(p => p.test(m[2]))) continue;
        if (hasThrottle) continue;

        findings.push(this.createFinding('warning',
          `Auth endpoint /${m[2]} tanpa rate limiting`,
          `Hacker bisa bruteforce: coba ribuan password per menit tanpa batasan.`,
          file, projectPath, { line: lineNum, code: text.trim(),
            suggestion: 'Install @nestjs/throttler, tambahkan @Throttle({ default: { limit: 5, ttl: 60000 } })' }));
      }
    }

    const appModule = path.join(srcPath, 'app.module.ts');
    if (fs.existsSync(appModule) && !fs.readFileSync(appModule, 'utf-8').includes('ThrottlerModule')) {
      findings.push(this.createFinding('warning', 'Tidak ada ThrottlerModule di AppModule',
        'API tidak punya rate limiting global — rentan bruteforce.', 'src/app.module.ts', projectPath));
    }

    return findings;
  }

  protected findFiles(dir: string, suffix: string): string[] {
    const r: string[] = [];
    try {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const f = path.join(dir, e.name);
        if (e.isDirectory() && e.name !== 'node_modules' && e.name !== 'dist') r.push(...this.findFiles(f, suffix));
        else if (e.isFile() && e.name.endsWith(suffix)) r.push(f);
      }
    } catch {}
    return r;
  }
}

