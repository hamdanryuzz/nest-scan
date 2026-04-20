import { BaseAnalyzer } from './base.analyzer';
import { Finding } from '../models/report.model';
import * as path from 'path';
import * as ts from 'typescript';
import {
  collectControllerSourceHints,
  collectMethodContexts,
  createTaintState,
  getNodeLine,
  getNodeSnippet,
  getObjectPropertyInitializer,
  getPropertyName,
  isPrismaLookupCall,
  TaintState,
} from './security-flow.util';

const OWNERSHIP_KEYS = [
  'userId',
  'ownerId',
  'createdBy',
  'accountId',
  'tenantId',
  'orgId',
  'organizationId',
  'merchantId',
];

export class IdorAnalyzer extends BaseAnalyzer {
  readonly name = 'idor';
  readonly description = 'Detects potential Insecure Direct Object Reference';

  async analyze(projectPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const srcPath = path.join(projectPath, 'src');
    const controllerHints = collectControllerSourceHints(projectPath);
    const methods = collectMethodContexts(
      srcPath,
      '.service.ts',
      file => !file.includes('.spec.') && !file.includes('.test.'),
    );

    for (const context of methods) {
      const hint = controllerHints.get(context.methodName);
      const taintedIndexes = new Set<number>(hint?.paramParamIndexes || []);

      context.parameterNames.forEach((name, index) => {
        if (/(^id$|Id$|_id$|uuid$)/i.test(name)) taintedIndexes.add(index);
      });

      if (taintedIndexes.size === 0 || !context.node.body) continue;

      const state = createTaintState(context, Array.from(taintedIndexes.values()));
      const hasControllerFlow = !!hint?.paramParamIndexes.length;

      const visit = (node: ts.Node) => {
        if (ts.isCallExpression(node) && isPrismaLookupCall(node, context.sourceFile)) {
          const firstArg = node.arguments[0];
          if (firstArg && ts.isObjectLiteralExpression(firstArg)) {
            const whereExpression = getObjectPropertyInitializer(firstArg, 'where');
            if (whereExpression) {
              const riskyField = this.findRiskyWhereField(whereExpression, state);
              const hasOwnership = this.hasOwnershipConstraint(whereExpression, state);

              if (riskyField && !hasOwnership) {
                const score = hasControllerFlow ? 92 : 71;
                const reason = hasControllerFlow
                  ? 'Route param dari controller mengalir ke prisma.where tanpa ownership check.'
                  : 'Parameter id-like dipakai di prisma.where, tetapi ownership check hanya terdeteksi lewat heuristik.';

                findings.push(this.createFinding(
                  'warning',
                  `Potensi IDOR di ${context.methodName}()`,
                  `Field "${riskyField}" dipakai untuk akses data langsung tanpa filter ownership. User bisa menukar ID dan membaca atau mengubah data milik orang lain.`,
                  context.file,
                  projectPath,
                  {
                    line: getNodeLine(context.sourceFile, node),
                    code: getNodeSnippet(context.sourceFile, node),
                    suggestion: 'Tambahkan filter ownership seperti userId/ownerId di where clause, atau validasi akses sebelum query.',
                    ...this.confidence(score, reason),
                  },
                ));
              }
            }
          }
        }

        ts.forEachChild(node, visit);
      };

      visit(context.node.body);
    }

    return findings;
  }

  private findRiskyWhereField(
    expression: ts.Expression,
    state: TaintState,
    seen = new Set<string>(),
  ): string | undefined {
    if (ts.isIdentifier(expression)) {
      if (seen.has(expression.text)) return undefined;
      seen.add(expression.text);
      const initializer = state.resolveInitializer(expression.text);
      return initializer ? this.findRiskyWhereField(initializer, state, seen) : undefined;
    }

    if (!ts.isObjectLiteralExpression(expression)) return undefined;

    for (const property of expression.properties) {
      if (ts.isPropertyAssignment(property)) {
        const name = getPropertyName(property.name);
        if (name && this.isIdLikeField(name) && state.isExpressionTainted(property.initializer)) {
          return name;
        }

        if (ts.isObjectLiteralExpression(property.initializer)) {
          const nested = this.findRiskyWhereField(property.initializer, state, seen);
          if (nested) return `${name || 'nested'}.${nested}`;
        }
      }

      if (ts.isShorthandPropertyAssignment(property)) {
        const name = property.name.text;
        if (this.isIdLikeField(name) && state.isExpressionTainted(property.name)) {
          return name;
        }
      }
    }

    return undefined;
  }

  private hasOwnershipConstraint(
    expression: ts.Expression,
    state: TaintState,
    seen = new Set<string>(),
  ): boolean {
    if (ts.isIdentifier(expression)) {
      if (seen.has(expression.text)) return false;
      seen.add(expression.text);
      const initializer = state.resolveInitializer(expression.text);
      if (initializer) return this.hasOwnershipConstraint(initializer, state, seen);
      return OWNERSHIP_KEYS.some(key => expression.text.toLowerCase().includes(key.toLowerCase()));
    }

    const text = expression.getText();
    if (OWNERSHIP_KEYS.some(key => text.includes(key))) return true;

    if (!ts.isObjectLiteralExpression(expression)) return false;

    for (const property of expression.properties) {
      if (ts.isPropertyAssignment(property)) {
        const name = getPropertyName(property.name);
        if (name && OWNERSHIP_KEYS.includes(name)) return true;
        if (ts.isObjectLiteralExpression(property.initializer) && this.hasOwnershipConstraint(property.initializer, state, seen)) {
          return true;
        }
      }

      if (ts.isShorthandPropertyAssignment(property) && OWNERSHIP_KEYS.includes(property.name.text)) {
        return true;
      }
    }

    return false;
  }

  private isIdLikeField(name: string): boolean {
    return name === 'id' || /Id$/i.test(name) || /_id$/i.test(name);
  }
}
