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

    // Check app-level throttler first
    const appModule = path.join(srcPath, 'app.module.ts');
    const hasGlobalThrottler = fs.existsSync(appModule) &&
      fs.readFileSync(appModule, 'utf-8').includes('ThrottlerModule');

    let foundAuthEndpoints = false;
    const controllers = this.findFiles(srcPath, '.controller.ts');

    for (const file of controllers) {
      const content = fs.readFileSync(file, 'utf-8');

      // If global throttler exists, per-file check is unnecessary
      if (hasGlobalThrottler) continue;

      const hasThrottle = content.includes('@Throttle') || content.includes('ThrottlerGuard');
      const lines = this.readLines(content);

      for (const { lineNum, text } of lines) {
        const m = text.match(/@(Post|Get)\s*\(\s*['"`]([^'"`]*)['"`]\)/);
        if (!m) continue;
        if (!this.AUTH_PATTERNS.some(p => p.test(m[2]))) continue;

        foundAuthEndpoints = true;
        if (hasThrottle) continue;

        findings.push(this.createFinding('warning',
          `Auth endpoint /${m[2]} tanpa rate limiting`,
          `Hacker bisa bruteforce endpoint ini — coba ribuan kombinasi per menit tanpa batasan.`,
          file, projectPath, { line: lineNum, code: text.trim(),
            suggestion: 'Install @nestjs/throttler, tambahkan @Throttle({ default: { limit: 5, ttl: 60000 } })' }));
      }
    }

    // Only warn about missing ThrottlerModule if auth endpoints were actually found
    if (!hasGlobalThrottler && foundAuthEndpoints) {
      findings.push(this.createFinding('warning', 'Tidak ada ThrottlerModule di AppModule',
        'Ada auth endpoint tapi tidak ada rate limiting global — rentan bruteforce.',
        'src/app.module.ts', projectPath));
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

