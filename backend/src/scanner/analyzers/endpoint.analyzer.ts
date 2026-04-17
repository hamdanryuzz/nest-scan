import { BaseAnalyzer } from './base.analyzer';
import { Finding, EndpointInfo } from '../models/report.model';
import * as fs from 'fs';
import * as path from 'path';

export class EndpointAnalyzer extends BaseAnalyzer {
  readonly name = 'endpoint-mapper';
  readonly description = 'Maps all API endpoints with their methods, guards, and parameters';

  // Store endpoints for external access
  public endpoints: EndpointInfo[] = [];

  async analyze(projectPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    this.endpoints = [];
    const srcPath = path.join(projectPath, 'src');
    if (!fs.existsSync(srcPath)) return findings;

    const controllerFiles = this.findFiles(srcPath, '.controller.ts');

    for (const file of controllerFiles) {
      const content = fs.readFileSync(file, 'utf-8');
      this.extractEndpoints(content, file, projectPath);
    }

    // Report endpoints without guards
    const unguarded = this.endpoints.filter(e => e.guards.length === 0);
    if (unguarded.length > 0) {
      findings.push(this.createFinding('info',
        `${this.endpoints.length} endpoints mapped, ${unguarded.length} tanpa guard`,
        `Total ${this.endpoints.length} endpoint ditemukan. ${unguarded.length} diantaranya tidak punya auth guard.`,
        'src/', projectPath));
    }

    return findings;
  }

  private extractEndpoints(content: string, file: string, projectPath: string): void {
    const lines = this.readLines(content);

    // Extract controller base path
    const controllerMatch = content.match(/@Controller\s*\(\s*['"`]([^'"`]*)['"`]\s*\)/);
    const basePath = controllerMatch ? controllerMatch[1] : '';

    // Extract controller class name
    const classMatch = content.match(/class\s+(\w+Controller)/);
    const controllerName = classMatch ? classMatch[1] : path.basename(file, '.ts');

    // Extract class-level guards
    const classGuards = this.extractGuards(content, true);

    for (let i = 0; i < lines.length; i++) {
      const text = lines[i].text;
      const httpMatch = text.match(/@(Get|Post|Patch|Put|Delete)\s*\(\s*(?:['"`]([^'"`]*)['"`])?\s*\)/);
      if (!httpMatch) continue;

      const method = httpMatch[1].toUpperCase() as EndpointInfo['method'];
      const routePath = httpMatch[2] || '';
      const fullPath = `/${basePath}/${routePath}`.replace(/\/+/g, '/').replace(/\/$/, '') || '/';

      // Extract method-level guards (look backward 5 lines)
      let methodGuards: string[] = [];
      for (let j = Math.max(0, i - 5); j < i; j++) {
        const guardMatch = lines[j].text.match(/@UseGuards\s*\(([^)]+)\)/);
        if (guardMatch) methodGuards.push(...this.parseGuardNames(guardMatch[1]));
      }

      const guards = methodGuards.length > 0 ? methodGuards : classGuards;

      // Extract handler name
      const handlerLine = lines.slice(i, Math.min(i + 3, lines.length)).map(l => l.text).join(' ');
      const handlerMatch = handlerLine.match(/async\s+(\w+)\s*\(/);
      const handler = handlerMatch ? handlerMatch[1] : 'unknown';

      // Extract params
      const params: string[] = [];
      const paramMatches = handlerLine.matchAll(/@Param\s*\(\s*['"`](\w+)['"`]\s*\)/g);
      for (const pm of paramMatches) params.push(pm[1]);

      // Check for @Body
      const hasBody = /@Body\(\)/.test(handlerLine);

      // Extract DTO name
      const dtoMatch = handlerLine.match(/@Body\(\)\s+\w+\s*:\s*(\w+)/);
      const dtoName = dtoMatch ? dtoMatch[1] : undefined;

      this.endpoints.push({
        method, path: fullPath, controller: controllerName,
        controllerFile: path.relative(projectPath, file).replace(/\\/g, '/'),
        handler, guards, pipes: [], dtoName, params, hasBody, line: lines[i].lineNum,
      });
    }
  }

  private extractGuards(content: string, classLevel: boolean): string[] {
    const guards: string[] = [];
    if (classLevel) {
      // Look for @UseGuards before the class declaration
      const classIndex = content.indexOf('class ');
      const beforeClass = content.substring(0, classIndex);
      const guardMatch = beforeClass.match(/@UseGuards\s*\(([^)]+)\)/);
      if (guardMatch) guards.push(...this.parseGuardNames(guardMatch[1]));
    }
    return guards;
  }

  private parseGuardNames(guardString: string): string[] {
    return guardString.split(',').map(g => g.trim()).filter(g => g.length > 0);
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

