import { BaseAnalyzer } from './base.analyzer';
import { Finding } from '../models/report.model';
import * as fs from 'fs';
import * as path from 'path';

export class ValidationAnalyzer extends BaseAnalyzer {
  readonly name = 'validation';
  readonly description = 'Checks DTOs for proper class-validator decorators';

  async analyze(projectPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const srcPath = path.join(projectPath, 'src');
    if (!fs.existsSync(srcPath)) return findings;

    const dtoFiles = this.findFiles(srcPath, '.dto.ts');
    for (const file of dtoFiles) {
      const content = fs.readFileSync(file, 'utf-8');
      this.checkMissingValidators(content, file, projectPath, findings);
    }

    const controllerFiles = this.findFiles(srcPath, '.controller.ts');
    for (const file of controllerFiles) {
      const content = fs.readFileSync(file, 'utf-8');
      this.checkMissingValidationPipe(content, file, projectPath, findings);
    }

    return findings;
  }

  private checkMissingValidators(content: string, file: string, projectPath: string, findings: Finding[]): void {
    if (!content.includes('class-validator') && !content.includes('class-transformer')) {
      // Check if file has class definitions with properties
      const hasClasses = /export\s+class\s+\w+/.test(content);
      const extendsPartial = /extends\s+PartialType/.test(content);

      if (hasClasses && !extendsPartial) {
        findings.push(this.createFinding('warning', 'DTO tanpa validation decorators',
          'DTO class tidak import class-validator. Field tidak divalidasi — user bisa kirim data invalid.',
          file, projectPath,
          { suggestion: 'Tambahkan decorator seperti @IsString(), @IsNotEmpty(), @IsEmail() di setiap field.' }));
      }
    }

    // Check individual properties without decorators
    const lines = this.readLines(content);
    for (let i = 0; i < lines.length; i++) {
      const text = lines[i].text;
      // Property declaration without decorator above it
      const propMatch = text.match(/^\s+(\w+)\s*[?:]?\s*:\s*(string|number|boolean|Date)/);
      if (!propMatch) continue;

      // Look backward for a decorator
      let hasDecorator = false;
      for (let j = Math.max(0, i - 5); j < i; j++) {
        if (lines[j].text.trim().startsWith('@')) {
          hasDecorator = true;
          break;
        }
      }

      if (!hasDecorator) {
        findings.push(this.createFinding('info', `Field "${propMatch[1]}" tanpa validation decorator`,
          `Property "${propMatch[1]}" (${propMatch[2]}) tidak punya validation decorator. Input tidak divalidasi.`,
          file, projectPath, { line: lines[i].lineNum, code: text.trim() }));
      }
    }
  }

  private checkMissingValidationPipe(content: string, file: string, projectPath: string, findings: Finding[]): void {
    const hasBody = /@Body\(\)/.test(content);
    const hasValidationPipe = /ValidationPipe|@UsePipes/.test(content);
    const hasGlobalPipe = content.includes('app.useGlobalPipes');

    if (hasBody && !hasValidationPipe && !hasGlobalPipe) {
      findings.push(this.createFinding('warning', 'Controller pakai @Body() tapi tanpa ValidationPipe',
        'Controller menerima request body tapi tidak ada ValidationPipe. DTO decorators tidak akan dijalankan.',
        file, projectPath,
        { suggestion: 'Tambahkan @UsePipes(new ValidationPipe()) di method/class, atau global pipe di main.ts.' }));
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

