import { BaseAnalyzer } from './base.analyzer';
import { Finding } from '../models/report.model';
import * as fs from 'fs';
import * as path from 'path';

export class PatternAnalyzer extends BaseAnalyzer {
  readonly name = 'pattern';
  readonly description = 'Checks for consistent error handling, response format, and coding patterns';

  async analyze(projectPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const srcPath = path.join(projectPath, 'src');
    if (!fs.existsSync(srcPath)) return findings;

    const controllerFiles = this.findFiles(srcPath, '.controller.ts');
    const serviceFiles = this.findFiles(srcPath, '.service.ts');

    for (const file of controllerFiles) {
      const content = fs.readFileSync(file, 'utf-8');
      this.checkErrorHandling(content, file, projectPath, findings);
      this.checkResponseFormat(content, file, projectPath, findings);
    }

    for (const file of serviceFiles) {
      const content = fs.readFileSync(file, 'utf-8');
      this.checkSoftDeletePattern(content, file, projectPath, findings);
      this.checkTimestampPattern(content, file, projectPath, findings);
    }

    return findings;
  }

  private checkErrorHandling(content: string, file: string, projectPath: string, findings: Finding[]): void {
    const httpMethods = this.findPattern(content, /@(Get|Post|Patch|Put|Delete)\(/);
    const tryCatches = (content.match(/try\s*\{/g) || []).length;

    if (httpMethods.length > 0 && tryCatches === 0) {
      findings.push(this.createFinding('warning', 'Controller tanpa try-catch',
        `Controller punya ${httpMethods.length} endpoint tapi tidak ada try-catch. Error tidak di-handle.`,
        file, projectPath,
        { suggestion: 'Wrap setiap handler dengan try-catch + errorResponse(), atau pakai global exception filter.' }));
    } else if (httpMethods.length > tryCatches && tryCatches > 0) {
      findings.push(this.createFinding('info',
        `${httpMethods.length - tryCatches} endpoint mungkin tanpa try-catch`,
        'Beberapa endpoint mungkin tidak punya error handling.',
        file, projectPath));
    }
  }

  private checkResponseFormat(content: string, file: string, projectPath: string, findings: Finding[]): void {
    const usesSuccessResponse = content.includes('successResponse(') || content.includes('successPaginationResponse(');
    const usesResJson = /res\.json\(/.test(content) || /res\.status\(\d+\)\.json/.test(content);

    if (usesSuccessResponse && usesResJson) {
      findings.push(this.createFinding('warning', 'Inconsistent response format',
        'Controller campuran antara helper response dan res.json() manual. API response format jadi tidak konsisten.',
        file, projectPath,
        { suggestion: 'Pilih satu: pakai successResponse() helper di semua endpoint, atau buat interceptor.' }));
    }
  }

  private checkSoftDeletePattern(content: string, file: string, projectPath: string, findings: Finding[]): void {
    // Check if remove/delete methods use soft delete or hard delete
    const hasDelete = content.includes('.delete(') || content.includes('.deleteMany(');
    const hasSoftDelete = content.includes("deletedAt");

    if (hasDelete && hasSoftDelete) {
      const deleteLines = this.findPattern(content, /prisma\.\w+\.delete\s*\(/);
      for (const dl of deleteLines) {
        findings.push(this.createFinding('warning', 'Hard delete di project yang pakai soft-delete',
          'File ini pakai prisma.xxx.delete() (hard delete) padahal juga pakai pola soft-delete (deletedAt). Bisa bikin data hilang permanen.',
          file, projectPath, { line: dl.lineNum, code: dl.text,
            suggestion: 'Ganti dengan update({ data: { deletedAt: now } }) untuk konsistensi.' }));
      }
    }
  }

  private checkTimestampPattern(content: string, file: string, projectPath: string, findings: Finding[]): void {
    const usesNewDate = this.findPattern(content, /new Date\(\)/);
    const usesHelper = content.includes('getAppNow()') || content.includes('getHongKongNow()');

    if (usesNewDate.length > 0 && usesHelper) {
      findings.push(this.createFinding('warning', 'Inconsistent timestamp — new Date() vs getAppNow()',
        `File ini campuran antara new Date() (${usesNewDate.length}x) dan getAppNow(). Timezone bisa inconsistent.`,
        file, projectPath, { line: usesNewDate[0].lineNum,
          suggestion: 'Pakai getAppNow() di semua tempat untuk konsistensi timezone.' }));
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

