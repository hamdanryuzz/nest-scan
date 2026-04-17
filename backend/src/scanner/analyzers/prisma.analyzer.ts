import { BaseAnalyzer } from './base.analyzer';
import { Finding } from '../models/report.model';
import * as fs from 'fs';
import * as path from 'path';

export class PrismaAnalyzer extends BaseAnalyzer {
  readonly name = 'prisma';
  readonly description = 'Audits Prisma schema for missing indexes, naming issues, and relation problems';

  async analyze(projectPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const schemaPath = path.join(projectPath, 'prisma', 'schema.prisma');
    if (!fs.existsSync(schemaPath)) return findings;

    const content = fs.readFileSync(schemaPath, 'utf-8');
    this.checkMissingIndexes(content, schemaPath, projectPath, findings);
    this.checkNamingInconsistency(content, schemaPath, projectPath, findings);
    this.checkRelationsWithoutOnDelete(content, schemaPath, projectPath, findings);
    this.checkSoftDeleteConsistency(content, schemaPath, projectPath, findings);

    return findings;
  }

  private checkMissingIndexes(content: string, file: string, projectPath: string, findings: Finding[]): void {
    const lines = this.readLines(content);
    const models: { name: string; startLine: number; fields: string[]; hasIndex: boolean }[] = [];

    let currentModel: typeof models[0] | null = null;
    for (const { lineNum, text } of lines) {
      const modelMatch = text.match(/^model\s+(\w+)\s*\{/);
      if (modelMatch) {
        currentModel = { name: modelMatch[1], startLine: lineNum, fields: [], hasIndex: false };
        models.push(currentModel);
        continue;
      }
      if (text.trim() === '}' && currentModel) { currentModel = null; continue; }
      if (!currentModel) continue;

      // Track foreign key fields
      const fkMatch = text.match(/^\s+(\w+Id)\s+String/);
      if (fkMatch) currentModel.fields.push(fkMatch[1]);

      if (text.includes('@@index') || text.includes('@@unique')) currentModel.hasIndex = true;
    }

    // Check FKs without indexes
    for (const model of models) {
      if (model.fields.length > 0 && !model.hasIndex) {
        findings.push(this.createFinding('info',
          `Model ${model.name} — FK tanpa index`,
          `Model "${model.name}" punya foreign key (${model.fields.join(', ')}) tapi tidak ada @@index. ` +
          `Query yang filter by FK akan lambat pada data besar.`,
          file, projectPath, { line: model.startLine,
            suggestion: `Tambahkan @@index([${model.fields[0]}]) di model ${model.name}.` }));
      }
    }
  }

  private checkNamingInconsistency(content: string, file: string, projectPath: string, findings: Finding[]): void {
    const lines = this.readLines(content);
    for (const { lineNum, text } of lines) {
      // Field names should be camelCase — check for PascalCase or snake_case fields
      const fieldMatch = text.match(/^\s+([A-Z]\w+)\s+(?:String|Int|Boolean|DateTime|Float)/);
      if (fieldMatch && !text.includes('model ') && !text.includes('enum ')) {
        findings.push(this.createFinding('warning',
          `Naming inconsistency: field "${fieldMatch[1]}" pakai PascalCase`,
          `Field "${fieldMatch[1]}" harusnya camelCase (${fieldMatch[1][0].toLowerCase() + fieldMatch[1].slice(1)}). ` +
          `Ini bisa bikin confusion di code dan API response.`,
          file, projectPath, { line: lineNum, code: text.trim() }));
      }

      // Enum names should be PascalCase
      const enumMatch = text.match(/^enum\s+([a-z]\w+)/);
      if (enumMatch) {
        findings.push(this.createFinding('info',
          `Enum "${enumMatch[1]}" pakai camelCase, harusnya PascalCase`,
          `Convention Prisma: enum name pakai PascalCase.`,
          file, projectPath, { line: lineNum }));
      }
    }
  }

  private checkRelationsWithoutOnDelete(content: string, file: string, projectPath: string, findings: Finding[]): void {
    const lines = this.readLines(content);
    for (const { lineNum, text } of lines) {
      if (text.includes('@relation(') && !text.includes('onDelete') && text.includes('fields:')) {
        const relationMatch = text.match(/@relation\([^)]*fields:\s*\[(\w+)\]/);
        findings.push(this.createFinding('info',
          `Relasi tanpa onDelete policy`,
          `Relasi ini tidak specify onDelete behavior. Default-nya RESTRICT — delete parent akan error kalau masih ada child.`,
          file, projectPath, { line: lineNum, code: text.trim(),
            suggestion: 'Tambahkan onDelete: Cascade, SetNull, atau Restrict sesuai kebutuhan.' }));
      }
    }
  }

  private checkSoftDeleteConsistency(content: string, file: string, projectPath: string, findings: Finding[]): void {
    const models = content.match(/model\s+\w+\s*\{[^}]+\}/gs) || [];
    const withSoftDelete: string[] = [];
    const withoutSoftDelete: string[] = [];

    for (const model of models) {
      const nameMatch = model.match(/model\s+(\w+)/);
      if (!nameMatch) continue;
      const name = nameMatch[1];
      const hasDeletedAt = model.includes('deletedAt');
      const hasCreatedAt = model.includes('createdAt');

      if (hasCreatedAt && !hasDeletedAt) withoutSoftDelete.push(name);
      if (hasDeletedAt) withSoftDelete.push(name);
    }

    if (withSoftDelete.length > 0 && withoutSoftDelete.length > 0) {
      findings.push(this.createFinding('info',
        'Soft-delete tidak konsisten across models',
        `${withSoftDelete.length} model pakai soft-delete (deletedAt), tapi ${withoutSoftDelete.length} model tidak: ` +
        `${withoutSoftDelete.join(', ')}. Ini bisa bikin confusion.`,
        file, projectPath));
    }
  }
}
