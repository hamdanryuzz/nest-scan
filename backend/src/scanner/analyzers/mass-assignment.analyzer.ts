import { BaseAnalyzer } from './base.analyzer';
import { Finding } from '../models/report.model';
import * as fs from 'fs';
import * as path from 'path';
import * as ts from 'typescript';
import {
  collectControllerSourceHints,
  collectMethodContexts,
  createTaintState,
  getNodeLine,
  getNodeSnippet,
  getObjectPropertyInitializer,
  isPrismaWriteCall,
  TaintState,
} from './security-flow.util';

type DataRiskKind = 'spread' | 'direct-object' | 'transformed-object';

export class MassAssignmentAnalyzer extends BaseAnalyzer {
  readonly name = 'mass-assignment';
  readonly description = 'Detects mass assignment vulnerabilities';

  async analyze(projectPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const srcPath = path.join(projectPath, 'src');
    const controllerHints = collectControllerSourceHints(projectPath);
    const serviceMethods = collectMethodContexts(
      srcPath,
      '.service.ts',
      file => !file.includes('.spec.') && !file.includes('.test.'),
    );

    for (const context of serviceMethods) {
      const hint = controllerHints.get(context.methodName);
      const taintedIndexes = new Set<number>(hint?.bodyParamIndexes || []);

      context.parameterNames.forEach((name, index) => {
        if (/(body|dto|input|payload|data)$/i.test(name)) taintedIndexes.add(index);
      });

      if (taintedIndexes.size === 0 || !context.node.body) continue;

      const state = createTaintState(context, Array.from(taintedIndexes.values()));
      const hasControllerFlow = !!hint?.bodyParamIndexes.length;

      const visit = (node: ts.Node) => {
        if (ts.isCallExpression(node) && isPrismaWriteCall(node, context.sourceFile)) {
          const firstArg = node.arguments[0];
          if (firstArg && ts.isObjectLiteralExpression(firstArg)) {
            const dataExpression = getObjectPropertyInitializer(firstArg, 'data');
            const risk = dataExpression ? this.assessDataRisk(dataExpression, state) : undefined;

            if (risk) {
              const score = this.scoreRisk(risk.kind, hasControllerFlow);
              const reason = hasControllerFlow
                ? 'Object dari @Body() mengalir ke prisma.data tanpa whitelist field yang jelas.'
                : 'Object yang terlihat seperti body/DTO mengalir ke prisma.data berdasarkan heuristik nama parameter.';

              findings.push(this.createFinding(
                'warning',
                'Mass Assignment - input user masuk ke Prisma data',
                `Object "${risk.label}" dipakai sebagai prisma.data melalui pola ${risk.kind}. Field sensitif seperti role atau isAdmin bisa ikut terisi kalau DTO tidak di-whitelist.`,
                context.file,
                projectPath,
                {
                  line: getNodeLine(context.sourceFile, node),
                  code: getNodeSnippet(context.sourceFile, node),
                  suggestion: 'Bangun object data secara eksplisit, misalnya data: { name: dto.name, email: dto.email }.',
                  ...this.confidence(score, reason),
                },
              ));
            }
          }
        }

        ts.forEachChild(node, visit);
      };

      visit(context.node.body);
    }

    for (const file of this.findFiles(srcPath, '.controller.ts')) {
      const content = fs.readFileSync(file, 'utf-8');
      for (const { lineNum, text } of this.readLines(content)) {
        if (/@Body\(\)\s+\w+\s*:\s*any/.test(text)) {
          findings.push(this.createFinding(
            'critical',
            '@Body() tipe any - tanpa validasi',
            'Request body tidak diketik dengan DTO. Semua field user bisa lolos ke layer berikutnya tanpa whitelist yang jelas.',
            file,
            projectPath,
            {
              line: lineNum,
              code: text.trim(),
              suggestion: 'Ganti any dengan DTO class dan aktifkan ValidationPipe.',
              ...this.confidence(96, 'Type body adalah any pada boundary controller, jadi input user praktis tidak dibatasi.'),
            },
          ));
        }
      }
    }

    return findings;
  }

  private assessDataRisk(expression: ts.Expression, state: TaintState): { kind: DataRiskKind; label: string } | undefined {
    if (ts.isIdentifier(expression)) {
      if (state.initialTaints.has(expression.text)) {
        return { kind: 'direct-object', label: expression.text };
      }

      const initializer = state.resolveInitializer(expression.text);
      if (initializer) return this.assessDataRisk(initializer, state) || (
        state.isExpressionTainted(initializer)
          ? { kind: 'transformed-object', label: expression.text }
          : undefined
      );

      return undefined;
    }

    if (ts.isObjectLiteralExpression(expression)) {
      for (const property of expression.properties) {
        if (ts.isSpreadAssignment(property) && state.isExpressionTainted(property.expression)) {
          return { kind: 'spread', label: property.expression.getText() };
        }
      }

      return undefined;
    }

    if (ts.isCallExpression(expression) && expression.arguments.some(arg => state.isExpressionTainted(arg))) {
      return { kind: 'transformed-object', label: expression.expression.getText() };
    }

    if (state.isExpressionTainted(expression)) {
      return { kind: 'transformed-object', label: expression.getText().slice(0, 60) };
    }

    return undefined;
  }

  private scoreRisk(kind: DataRiskKind, hasControllerFlow: boolean): number {
    if (hasControllerFlow && kind === 'spread') return 93;
    if (hasControllerFlow && kind === 'direct-object') return 89;
    if (hasControllerFlow) return 67;
    if (kind === 'spread') return 78;
    if (kind === 'direct-object') return 74;
    return 58;
  }
}
