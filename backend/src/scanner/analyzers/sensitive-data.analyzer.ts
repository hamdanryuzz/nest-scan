import { BaseAnalyzer } from './base.analyzer';
import { Finding } from '../models/report.model';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Sensitive Data & Hardcoded Secrets Scanner
 */
export class SensitiveDataAnalyzer extends BaseAnalyzer {
  readonly name = 'sensitive-data';
  readonly description = 'Detects password exposure in responses and hardcoded secrets';

  private readonly SECRET_PATTERNS = [
    { pattern: /['"`](?:sk[-_]live|sk[-_]test|pk[-_]live|pk[-_]test)[-_]\w{10,}['"`]/, name: 'Stripe API Key' },
    { pattern: /['"`]ghp_\w{30,}['"`]/, name: 'GitHub PAT' },
    { pattern: /['"`]glpat-\w{20,}['"`]/, name: 'GitLab PAT' },
    { pattern: /['"`]xox[bporas]-\w{10,}['"`]/, name: 'Slack Token' },
    { pattern: /['"`]AKIA[0-9A-Z]{16}['"`]/, name: 'AWS Access Key' },
    { pattern: /['"`]Bearer\s+[A-Za-z0-9\-._~+\/]+=*['"`]/, name: 'Bearer Token' },
  ];

  private readonly SENSITIVE_FIELDS = ['password', 'passwordHash', 'secret', 'token', 'refreshToken', 'apiKey', 'accessKey', 'secretKey'];

  async analyze(projectPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const srcPath = path.join(projectPath, 'src');
    if (!fs.existsSync(srcPath)) return findings;

    const tsFiles = this.findFiles(srcPath, '.ts');
    for (const file of tsFiles) {
      const content = fs.readFileSync(file, 'utf-8');
      this.checkHardcodedSecrets(content, file, projectPath, findings);
      this.checkPasswordExposure(content, file, projectPath, findings);
      this.checkEnvInCode(content, file, projectPath, findings);
    }

    // Check if .env is committed
    this.checkEnvFile(projectPath, findings);

    return findings;
  }

  private checkHardcodedSecrets(content: string, file: string, projectPath: string, findings: Finding[]): void {
    if (file.includes('.spec.') || file.includes('.test.') || file.includes('node_modules')) return;
    const lines = this.readLines(content);

    for (const { lineNum, text } of lines) {
      for (const { pattern, name } of this.SECRET_PATTERNS) {
        if (pattern.test(text)) {
          findings.push(this.createFinding('critical', `Hardcoded Secret — ${name}`,
            `${name} hardcoded di source code. Siapapun yang akses repo bisa pakai credential ini.`,
            file, projectPath, { line: lineNum, code: text.trim().substring(0, 100) + '...',
              suggestion: 'Pindahkan ke environment variable (.env) dan akses via process.env.' }));
        }
      }

      // Check for password/secret variable assignments with string literals
      const varAssignMatch = text.match(/(?:const|let|var)\s+(password|secret|apiKey|secretKey|accessKey)\s*=\s*['"`][^'"`]{3,}['"`]/i);
      if (varAssignMatch) {
        findings.push(this.createFinding('critical', `Hardcoded ${varAssignMatch[1]}`,
          `Variable "${varAssignMatch[1]}" di-assign string literal. Credential tidak boleh di-hardcode.`,
          file, projectPath, { line: lineNum, code: text.trim(),
            suggestion: 'Gunakan process.env atau config service.' }));
      }
    }
  }

  private checkPasswordExposure(content: string, file: string, projectPath: string, findings: Finding[]): void {
    if (!file.endsWith('.service.ts')) return;
    const lines = this.readLines(content);

    for (let i = 0; i < lines.length; i++) {
      const text = lines[i].text;
      // Check prisma queries that fetch password-containing models without select/exclusion
      const queryMatch = text.match(/prisma\.(\w+)\.(findFirst|findUnique|findMany)\s*\(/);
      if (!queryMatch) continue;

      const modelName = queryMatch[1].toLowerCase();
      const passwordModels = ['admin', 'user', 'merchantuser', 'merchant_user', 'promotionEventAccount'];
      if (!passwordModels.some(m => modelName.includes(m.toLowerCase()))) continue;

      // Look ahead for select clause or password exclusion
      const methodBlock = lines.slice(i, Math.min(i + 15, lines.length)).map(l => l.text).join('\n');
      const hasSelect = /select\s*:/.test(methodBlock);
      const hasPasswordExclusion = /password\s*[:,]\s*(?:undefined|false)|{\s*password\s*,\s*\.\.\./.test(methodBlock);
      const hasOmit = /omit\s*:/.test(methodBlock);

      if (!hasSelect && !hasPasswordExclusion && !hasOmit) {
        findings.push(this.createFinding('warning',
          `Password mungkin terekspos dari ${queryMatch[1]}.${queryMatch[2]}()`,
          `Query ke model "${queryMatch[1]}" tanpa select/omit. Field password bisa ikut ter-return ke API response.\n` +
          `Hacker bisa crack password hash offline pakai tools seperti hashcat.`,
          file, projectPath, { line: lines[i].lineNum, code: text.trim(),
            suggestion: 'Tambahkan select clause atau destructure { password, ...safe } = result.' }));
      }
    }
  }

  private checkEnvInCode(content: string, file: string, projectPath: string, findings: Finding[]): void {
    const lines = this.readLines(content);
    for (const { lineNum, text } of lines) {
      // JWT secret hardcoded
      if (/jwt\.sign\s*\([^)]+,\s*['"`][^'"`]{3,}['"`]/.test(text)) {
        findings.push(this.createFinding('critical', 'JWT Secret hardcoded',
          'JWT secret di-hardcode. Hacker bisa bikin token valid sendiri kalau tau secret-nya.',
          file, projectPath, { line: lineNum, code: text.trim(),
            suggestion: 'Gunakan process.env.JWT_SECRET atau ConfigService.' }));
      }
    }
  }

  private checkEnvFile(projectPath: string, findings: Finding[]): void {
    const gitignorePath = path.join(projectPath, '.gitignore');
    const envPath = path.join(projectPath, '.env');

    if (fs.existsSync(envPath)) {
      let envIgnored = false;
      if (fs.existsSync(gitignorePath)) {
        const gitignore = fs.readFileSync(gitignorePath, 'utf-8');
        envIgnored = gitignore.split('\n').some(line => line.trim() === '.env' || line.trim() === '.env*');
      }

      if (!envIgnored) {
        findings.push(this.createFinding('critical', '.env file mungkin ter-commit ke git',
          '.env file ada di project tapi tidak ada di .gitignore. Credential bisa ter-expose di repository.',
          '.gitignore', projectPath,
          { suggestion: 'Tambahkan .env ke .gitignore dan hapus dari git history.' }));
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

