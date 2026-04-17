import { Injectable, Logger } from '@nestjs/common';
import { GitHubApiService, RepoFile } from './git/github-api.service';
import { GemmaService } from './ai/gemma.service';
import { ScanReport, ScanRequest, Finding } from './models/report.model';
import { AuthGuardAnalyzer } from './analyzers/auth-guard.analyzer';
import { IdorAnalyzer } from './analyzers/idor.analyzer';
import { InjectionAnalyzer } from './analyzers/injection.analyzer';
import { MassAssignmentAnalyzer } from './analyzers/mass-assignment.analyzer';
import { SensitiveDataAnalyzer } from './analyzers/sensitive-data.analyzer';
import { ValidationAnalyzer } from './analyzers/validation.analyzer';
import { TypeSafetyAnalyzer } from './analyzers/type-safety.analyzer';
import { EndpointAnalyzer } from './analyzers/endpoint.analyzer';
import { PrismaAnalyzer } from './analyzers/prisma.analyzer';
import { PatternAnalyzer } from './analyzers/pattern.analyzer';
import { CodeSmellAnalyzer } from './analyzers/code-smell.analyzer';
import { RateLimitAnalyzer } from './analyzers/rate-limit.analyzer';
import { ModuleAnalyzer } from './analyzers/module.analyzer';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

@Injectable()
export class ScannerService {
  private readonly logger = new Logger(ScannerService.name);

  constructor(
    private readonly github: GitHubApiService,
    private readonly gemma: GemmaService,
  ) {}

  async scan(request: ScanRequest): Promise<ScanReport> {
    const startTime = Date.now();
    const { owner, repo } = this.github.parseRepoUrl(request.repoUrl);

    // 1. Fetch files via GitHub API
    this.logger.log(`Fetching ${owner}/${repo}@${request.branch} via GitHub API`);
    const files = await this.github.fetchProjectFiles(owner, repo, request.branch, request.pat);

    // 2. Write files to temp dir for analyzers (they expect filesystem)
    const tmpDir = path.join(os.tmpdir(), `nest-scan-${Date.now()}`);
    this.writeFilesToDisk(files, tmpDir);

    try {
      // 3. Run all analyzers
      const endpointAnalyzer = new EndpointAnalyzer();
      const moduleAnalyzer = new ModuleAnalyzer();
      const analyzers = [
        new AuthGuardAnalyzer(), new IdorAnalyzer(), new InjectionAnalyzer(),
        new MassAssignmentAnalyzer(), new SensitiveDataAnalyzer(), new RateLimitAnalyzer(),
        new ValidationAnalyzer(), new TypeSafetyAnalyzer(), new PatternAnalyzer(),
        new CodeSmellAnalyzer(), endpointAnalyzer, new PrismaAnalyzer(), moduleAnalyzer,
      ];

      const allFindings: Finding[] = [];
      for (const analyzer of analyzers) {
        try {
          const findings = await analyzer.analyze(tmpDir);
          allFindings.push(...findings);
          this.logger.log(`${analyzer.name}: ${findings.length} findings`);
        } catch (error: any) {
          this.logger.error(`${analyzer.name} failed: ${error.message}`);
        }
      }

      // 4. Enrich findings with actual code snippets from fetched files
      const fileMap = new Map(files.map(f => [f.path, f.content]));
      for (const finding of allFindings) {
        if (finding.file && !finding.code) {
          const content = fileMap.get(finding.file) || fileMap.get('src/' + finding.file);
          if (content && finding.line) {
            const lines = content.split('\n');
            const start = Math.max(0, finding.line - 3);
            const end = Math.min(lines.length, finding.line + 5);
            finding.code = lines.slice(start, end)
              .map((l, i) => `${start + i + 1}${start + i + 1 === finding.line ? ' →' : '  '} ${l}`)
              .join('\n');
          }
        }
      }

      // 5. AI Review (if GEMINI_API_KEY set in .env)
      let aiReview = undefined;
      if (this.gemma.isEnabled) {
        aiReview = await this.gemma.reviewFindings(allFindings, fileMap);
      }

      // 6. Build report
      const report: ScanReport = {
        id: `scan-${Date.now()}`,
        repoUrl: request.repoUrl,
        branch: request.branch,
        scannedAt: new Date().toISOString(),
        summary: {
          critical: allFindings.filter(f => f.severity === 'critical').length,
          warning: allFindings.filter(f => f.severity === 'warning').length,
          info: allFindings.filter(f => f.severity === 'info').length,
          totalFiles: files.length,
          totalModules: moduleAnalyzer.modules.length,
          totalEndpoints: endpointAnalyzer.endpoints.length,
          scanDurationMs: Date.now() - startTime,
        },
        findings: allFindings,
        endpoints: endpointAnalyzer.endpoints,
        modules: moduleAnalyzer.modules,
        aiReview,
      };

      this.logger.log(`Scan complete: ${allFindings.length} findings in ${report.summary.scanDurationMs}ms`);
      return report;

    } finally {
      // Cleanup temp dir
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  }

  private writeFilesToDisk(files: RepoFile[], baseDir: string): void {
    for (const file of files) {
      const fullPath = path.join(baseDir, file.path);
      const dir = path.dirname(fullPath);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(fullPath, file.content, 'utf-8');
    }
  }
}
