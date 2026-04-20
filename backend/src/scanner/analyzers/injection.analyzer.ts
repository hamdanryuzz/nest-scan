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
  isPrismaRawCall,
  isSafeTaggedPrismaRaw,
  TaintState,
} from './security-flow.util';

type RawQueryRisk = 'tainted-concat' | 'tainted-template' | 'unsafe-api' | 'dynamic-helper';

export class InjectionAnalyzer extends BaseAnalyzer {
  readonly name = 'injection';
  readonly description = 'Detects SQL injection and code injection';

  async analyze(projectPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const srcPath = path.join(projectPath, 'src');
    const controllerHints = collectControllerSourceHints(projectPath);
    const methods = collectMethodContexts(
      srcPath,
      '.ts',
      file => !file.includes('.spec.') && !file.includes('.test.'),
    );

    for (const context of methods) {
      const hint = controllerHints.get(context.methodName);
      const taintedIndexes = new Set<number>([
        ...(hint?.bodyParamIndexes || []),
        ...(hint?.paramParamIndexes || []),
        ...(hint?.queryParamIndexes || []),
      ]);

      context.parameterNames.forEach((name, index) => {
        if (/(id|query|filter|search|term|input|body|dto|payload|sql)$/i.test(name)) {
          taintedIndexes.add(index);
        }
      });

      const state = createTaintState(context, Array.from(taintedIndexes.values()));
      const hasControllerFlow = !!(
        hint?.bodyParamIndexes.length ||
        hint?.paramParamIndexes.length ||
        hint?.queryParamIndexes.length
      );

      const visit = (node: ts.Node) => {
        if (ts.isTaggedTemplateExpression(node) && isSafeTaggedPrismaRaw(node, context.sourceFile)) {
          return;
        }

        if (ts.isCallExpression(node)) {
          const rawRisk = isPrismaRawCall(node, context.sourceFile)
            ? this.assessRawQuery(node, state, context.sourceFile)
            : undefined;

          if (rawRisk) {
            const score = this.scoreRawRisk(rawRisk.kind, hasControllerFlow);
            const reason = hasControllerFlow
              ? 'Input request dari controller ikut menyusun raw query.'
              : 'Query disusun secara dinamis oleh variabel yang terlihat berasal dari input method.';

            findings.push(this.createFinding(
              'critical',
              'SQL Injection - raw query dibangun dari input dinamis',
              `Raw query menggunakan pola ${rawRisk.kind}. Input user bisa ikut menyusun string SQL sebelum dikirim ke database.`,
              context.file,
              projectPath,
              {
                line: getNodeLine(context.sourceFile, node),
                code: getNodeSnippet(context.sourceFile, node),
                suggestion: 'Gunakan tagged template prisma.$queryRaw`... ${value}` atau query builder yang mem-parameterize input.',
                ...this.confidence(score, reason),
              },
            ));
          }

          const evalRisk = this.assessEvalRisk(node, state, context.sourceFile);
          if (evalRisk) {
            findings.push(this.createFinding(
              evalRisk.severity,
              evalRisk.title,
              evalRisk.description,
              context.file,
              projectPath,
              {
                line: getNodeLine(context.sourceFile, node),
                code: getNodeSnippet(context.sourceFile, node),
                ...this.confidence(evalRisk.score, evalRisk.reason),
              },
            ));
          }
        }

        if (ts.isNewExpression(node)) {
          const constructorRisk = this.assessFunctionConstructorRisk(node, state);
          if (constructorRisk) {
            findings.push(this.createFinding(
              constructorRisk.severity,
              constructorRisk.title,
              constructorRisk.description,
              context.file,
              projectPath,
              {
                line: getNodeLine(context.sourceFile, node),
                code: getNodeSnippet(context.sourceFile, node),
                ...this.confidence(constructorRisk.score, constructorRisk.reason),
              },
            ));
          }
        }

        ts.forEachChild(node, visit);
      };

      if (context.node.body) visit(context.node.body);
    }

    return findings;
  }

  private assessRawQuery(
    call: ts.CallExpression,
    state: TaintState,
    sourceFile: ts.SourceFile,
  ): { kind: RawQueryRisk } | undefined {
    const expressionText = call.expression.getText(sourceFile);
    const isUnsafeApi = /\$(queryRawUnsafe|executeRawUnsafe)$/.test(expressionText);
    const firstArg = call.arguments[0];
    if (!firstArg) return isUnsafeApi ? { kind: 'unsafe-api' } : undefined;

    if (this.isTaintedStringConcat(firstArg, state)) return { kind: 'tainted-concat' };
    if (this.isTaintedTemplate(firstArg, state)) return { kind: 'tainted-template' };

    if (isUnsafeApi && state.isExpressionTainted(firstArg)) return { kind: 'unsafe-api' };
    if (isUnsafeApi && !ts.isStringLiteral(firstArg) && !ts.isNoSubstitutionTemplateLiteral(firstArg)) {
      return { kind: 'dynamic-helper' };
    }

    if (ts.isIdentifier(firstArg)) {
      const initializer = state.resolveInitializer(firstArg.text);
      if (initializer) {
        if (this.isTaintedStringConcat(initializer, state)) return { kind: 'tainted-concat' };
        if (this.isTaintedTemplate(initializer, state)) return { kind: 'tainted-template' };
        if (state.isExpressionTainted(initializer)) return { kind: 'dynamic-helper' };
      }
    }

    return undefined;
  }

  private assessEvalRisk(
    call: ts.CallExpression,
    state: TaintState,
    sourceFile: ts.SourceFile,
  ): { severity: 'critical' | 'warning'; title: string; description: string; score: number; reason: string } | undefined {
    if (ts.isIdentifier(call.expression) && call.expression.text === 'eval') {
      const arg = call.arguments[0];
      if (!arg) return undefined;

      if (state.isExpressionTainted(arg)) {
        return {
          severity: 'critical',
          title: 'Code Injection - eval() menerima input dinamis',
          description: 'eval() mengeksekusi string yang terbentuk dari input dinamis. Ini bisa berubah menjadi remote code execution.',
          score: 95,
          reason: 'Argumen eval() terbukti tainted oleh input method atau alur turunannya.',
        };
      }

      return {
        severity: 'warning',
        title: 'eval() dipakai dengan string dinamis',
        description: 'eval() masih berisiko walau alur input user belum terbukti. Pertimbangkan menghapus pola ini.',
        score: 61,
        reason: `Pemanggilan ${call.expression.getText(sourceFile)} terdeteksi, tetapi alur input user belum dapat dibuktikan penuh.`,
      };
    }

    if (ts.isIdentifier(call.expression) && call.expression.text === 'Function') {
      if (call.arguments.some(arg => state.isExpressionTainted(arg))) {
        return {
          severity: 'critical',
          title: 'Code Injection - Function() menerima input dinamis',
          description: 'Function() menyusun kode dari string dinamis. Jika input user ikut masuk, risikonya setara eval().',
          score: 93,
          reason: 'Argumen Function() ikut membawa data yang tainted.',
        };
      }

      return {
        severity: 'warning',
        title: 'Function() dipakai dengan string dinamis',
        description: 'Pola Function() rawan code injection walau alur input user belum terbukti penuh.',
        score: 60,
        reason: 'Pemanggilan Function() terdeteksi, tetapi alur input user belum dapat dibuktikan penuh.',
      };
    }

    return undefined;
  }

  private assessFunctionConstructorRisk(
    node: ts.NewExpression,
    state: TaintState,
  ): { severity: 'critical' | 'warning'; title: string; description: string; score: number; reason: string } | undefined {
    if (!ts.isIdentifier(node.expression) || node.expression.text !== 'Function') return undefined;
    const args = node.arguments || [];
    if (args.some(arg => state.isExpressionTainted(arg))) {
      return {
        severity: 'critical',
        title: 'Code Injection - new Function() menerima input dinamis',
        description: 'new Function() menyusun kode dari string dinamis. Jika input user ikut masuk, risikonya setara eval().',
        score: 93,
        reason: 'Argumen new Function() ikut membawa data yang tainted.',
      };
    }

    return {
      severity: 'warning',
      title: 'new Function() dipakai dengan string dinamis',
      description: 'Pola new Function() rawan code injection walau alur input user belum terbukti penuh.',
      score: 60,
      reason: 'Pemanggilan new Function() terdeteksi, tetapi alur input user belum dapat dibuktikan penuh.',
    };
  }

  private isTaintedStringConcat(expression: ts.Expression, state: TaintState): boolean {
    if (ts.isBinaryExpression(expression) && expression.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      return state.isExpressionTainted(expression.left) || state.isExpressionTainted(expression.right);
    }

    if (ts.isIdentifier(expression)) {
      const initializer = state.resolveInitializer(expression.text);
      return initializer ? this.isTaintedStringConcat(initializer, state) : false;
    }

    return false;
  }

  private isTaintedTemplate(expression: ts.Expression, state: TaintState): boolean {
    if (ts.isTemplateExpression(expression)) {
      return expression.templateSpans.some(span => state.isExpressionTainted(span.expression));
    }

    if (ts.isIdentifier(expression)) {
      const initializer = state.resolveInitializer(expression.text);
      return initializer ? this.isTaintedTemplate(initializer, state) : false;
    }

    return false;
  }

  private scoreRawRisk(kind: RawQueryRisk, hasControllerFlow: boolean): number {
    if (hasControllerFlow && kind === 'tainted-concat') return 96;
    if (hasControllerFlow && kind === 'tainted-template') return 94;
    if (hasControllerFlow && kind === 'unsafe-api') return 90;
    if (hasControllerFlow) return 70;
    if (kind === 'unsafe-api') return 75;
    if (kind === 'dynamic-helper') return 63;
    return 82;
  }
}
