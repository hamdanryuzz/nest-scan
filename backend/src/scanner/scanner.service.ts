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
      const visibleFindings = this.sortFindings(
        this.applySuppressions(allFindings, fileMap),
      );

      for (const finding of visibleFindings) {
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
        aiReview = await this.gemma.reviewFindings(visibleFindings, fileMap);
      }

      // 6. Build report
      const report: ScanReport = {
        id: `scan-${Date.now()}`,
        repoUrl: request.repoUrl,
        branch: request.branch,
        scannedAt: new Date().toISOString(),
        summary: {
          critical: visibleFindings.filter(f => f.severity === 'critical').length,
          warning: visibleFindings.filter(f => f.severity === 'warning').length,
          info: visibleFindings.filter(f => f.severity === 'info').length,
          totalFiles: files.length,
          totalModules: moduleAnalyzer.modules.length,
          totalEndpoints: endpointAnalyzer.endpoints.length,
          scanDurationMs: Date.now() - startTime,
        },
        findings: visibleFindings,
        endpoints: endpointAnalyzer.endpoints,
        modules: moduleAnalyzer.modules,
        aiReview,
      };

      this.logger.log(`Scan complete: ${visibleFindings.length} findings in ${report.summary.scanDurationMs}ms`);
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

  private applySuppressions(findings: Finding[], fileMap: Map<string, string>): Finding[] {
    let suppressed = 0;
    const visible = findings.filter(finding => {
      const content = fileMap.get(finding.file) || fileMap.get(`src/${finding.file}`);
      const isSuppressed = !!content && this.findSuppression(finding, content);
      if (isSuppressed) suppressed += 1;
      return !isSuppressed;
    });

    if (suppressed > 0) {
      this.logger.log(`Suppressed ${suppressed} finding(s) via nest-scan ignore directives`);
    }

    return visible;
  }

  private findSuppression(finding: Finding, content: string): string | undefined {
    const lines = content.split('\n');
    const analyzer = finding.analyzer.toLowerCase();

    const matchesAnalyzer = (raw: string) => {
      const tokens = raw
        .split(/[,\s]+/)
        .map(token => token.trim().toLowerCase())
        .filter(Boolean);

      return tokens.includes('all') || tokens.includes(analyzer);
    };

    for (const line of lines) {
      const fileMatch = line.match(/nest-scan-ignore-file\s+([a-z0-9-_,\s]+)/i);
      if (fileMatch && matchesAnalyzer(fileMatch[1])) return 'comment:file';
    }

    if (!finding.line) return undefined;

    const currentIndex = Math.max(0, finding.line - 1);
    const nearbyStart = Math.max(0, currentIndex - 2);
    const nearbyLines = lines.slice(nearbyStart, currentIndex + 1);
    for (const line of nearbyLines) {
      const inlineMatch = line.match(/nest-scan-ignore\s+([a-z0-9-_,\s]+)/i);
      if (inlineMatch && matchesAnalyzer(inlineMatch[1])) return 'comment:inline';
    }

    const prevLine = lines[currentIndex - 1];
    if (prevLine) {
      const nextLineMatch = prevLine.match(/nest-scan-ignore-next-line\s+([a-z0-9-_,\s]+)/i);
      if (nextLineMatch && matchesAnalyzer(nextLineMatch[1])) return 'comment:next-line';
    }

    const decoratorWindow = lines
      .slice(Math.max(0, currentIndex - 5), currentIndex + 1)
      .join('\n');
    const decoratorPattern = /@NestScanIgnore\s*\(([\s\S]*?)\)/gi;
    let match: RegExpExecArray | null;
    while ((match = decoratorPattern.exec(decoratorWindow))) {
      const normalized = match[1].replace(/[[\]'"\s]/g, ' ');
      if (matchesAnalyzer(normalized)) return 'decorator';
    }

    return undefined;
  }

  private sortFindings(findings: Finding[]): Finding[] {
    const severityWeight: Record<Finding['severity'], number> = {
      critical: 3,
      warning: 2,
      info: 1,
    };

    return [...findings].sort((a, b) => {
      if (severityWeight[b.severity] !== severityWeight[a.severity]) {
        return severityWeight[b.severity] - severityWeight[a.severity];
      }
      if (b.confidenceScore !== a.confidenceScore) {
        return b.confidenceScore - a.confidenceScore;
      }
      return a.title.localeCompare(b.title);
    });
  }
}
