import * as fs from 'fs';
import * as path from 'path';
import * as ts from 'typescript';

export type InputSourceKind = 'body' | 'param' | 'query';

export interface ControllerSourceHints {
  bodyParamIndexes: number[];
  paramParamIndexes: number[];
  queryParamIndexes: number[];
  callCount: number;
}

export interface MethodContext {
  file: string;
  className: string;
  methodName: string;
  line: number;
  parameterNames: string[];
  sourceFile: ts.SourceFile;
  node: ts.MethodDeclaration;
}

export interface TaintState {
  initialTaints: Set<string>;
  resolveInitializer(name: string): ts.Expression | undefined;
  isExpressionTainted(expression?: ts.Node, seen?: Set<string>): boolean;
}

export function findProjectFiles(dir: string, suffix: string): string[] {
  const results: string[] = [];
  try {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory() && !['node_modules', 'dist', '.git'].includes(entry.name)) {
        results.push(...findProjectFiles(full, suffix));
      } else if (entry.isFile() && entry.name.endsWith(suffix)) {
        results.push(full);
      }
    }
  } catch {
    return results;
  }

  return results;
}

export function collectMethodContexts(
  dir: string,
  suffix: string,
  shouldInclude?: (file: string) => boolean,
): MethodContext[] {
  const contexts: MethodContext[] = [];

  for (const file of findProjectFiles(dir, suffix)) {
    if (shouldInclude && !shouldInclude(file)) continue;

    const content = fs.readFileSync(file, 'utf-8');
    const sourceFile = ts.createSourceFile(file, content, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);

    const visit = (node: ts.Node, className = 'unknown') => {
      if (ts.isClassDeclaration(node) && node.name) {
        ts.forEachChild(node, child => visit(child, node.name!.text));
        return;
      }

      if (ts.isMethodDeclaration(node) && node.body && node.name && ts.isIdentifier(node.name)) {
        contexts.push({
          file,
          className,
          methodName: node.name.text,
          line: getNodeLine(sourceFile, node),
          parameterNames: node.parameters.map(param => getBindingNames(param.name)[0] || `arg${contexts.length}`),
          sourceFile,
          node,
        });
      }

      ts.forEachChild(node, child => visit(child, className));
    };

    visit(sourceFile);
  }

  return contexts;
}

export function collectControllerSourceHints(projectPath: string): Map<string, ControllerSourceHints> {
  const srcPath = path.join(projectPath, 'src');
  const hints = new Map<string, { body: Set<number>; param: Set<number>; query: Set<number>; callCount: number }>();

  for (const file of findProjectFiles(srcPath, '.controller.ts')) {
    const content = fs.readFileSync(file, 'utf-8');
    const sourceFile = ts.createSourceFile(file, content, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);

    const visit = (node: ts.Node) => {
      if (ts.isMethodDeclaration(node) && node.body && node.name && ts.isIdentifier(node.name)) {
        const bodyParams = new Set<string>();
        const routeParams = new Set<string>();
        const queryParams = new Set<string>();

        node.parameters.forEach(param => {
          const sourceKind = getParameterSourceKind(param);
          const names = getBindingNames(param.name);
          if (sourceKind === 'body') names.forEach(name => bodyParams.add(name));
          if (sourceKind === 'param') names.forEach(name => routeParams.add(name));
          if (sourceKind === 'query') names.forEach(name => queryParams.add(name));
        });

        const register = (call: ts.CallExpression) => {
          const callInfo = getServiceCallInfo(call);
          if (!callInfo) return;

          const bucket = hints.get(callInfo.methodName) || {
            body: new Set<number>(),
            param: new Set<number>(),
            query: new Set<number>(),
            callCount: 0,
          };

          call.arguments.forEach((arg, index) => {
            if (expressionReferencesNames(arg, bodyParams)) bucket.body.add(index);
            if (expressionReferencesNames(arg, routeParams)) bucket.param.add(index);
            if (expressionReferencesNames(arg, queryParams)) bucket.query.add(index);
          });

          bucket.callCount += 1;
          hints.set(callInfo.methodName, bucket);
        };

        const walkBody = (child: ts.Node) => {
          if (ts.isCallExpression(child)) register(child);
          ts.forEachChild(child, walkBody);
        };

        walkBody(node.body);
      }

      ts.forEachChild(node, visit);
    };

    visit(sourceFile);
  }

  return new Map(
    Array.from(hints.entries()).map(([methodName, value]) => [
      methodName,
      {
        bodyParamIndexes: Array.from(value.body.values()).sort((a, b) => a - b),
        paramParamIndexes: Array.from(value.param.values()).sort((a, b) => a - b),
        queryParamIndexes: Array.from(value.query.values()).sort((a, b) => a - b),
        callCount: value.callCount,
      },
    ]),
  );
}

export function createTaintState(context: MethodContext, taintedParameterIndexes: number[]): TaintState {
  const initialTaints = new Set<string>();
  taintedParameterIndexes.forEach(index => {
    const name = context.parameterNames[index];
    if (name) initialTaints.add(name);
  });

  const initializers = new Map<string, ts.Expression>();

  const registerBinding = (binding: ts.BindingName, expression?: ts.Expression) => {
    if (!expression) return;

    if (ts.isIdentifier(binding)) {
      initializers.set(binding.text, expression);
      return;
    }

    if (ts.isObjectBindingPattern(binding) || ts.isArrayBindingPattern(binding)) {
      binding.elements.forEach(element => {
        if (ts.isBindingElement(element)) registerBinding(element.name, expression);
      });
    }
  };

  const collectAssignments = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      registerBinding(node.name, node.initializer);
    }

    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(node.left)
    ) {
      initializers.set(node.left.text, node.right);
    }

    ts.forEachChild(node, collectAssignments);
  };

  collectAssignments(context.node.body!);

  const resolveInitializer = (name: string): ts.Expression | undefined => initializers.get(name);

  const isExpressionTainted = (expression?: ts.Node, seen = new Set<string>()): boolean => {
    if (!expression) return false;

    if (ts.isIdentifier(expression)) {
      if (initialTaints.has(expression.text)) return true;
      if (seen.has(expression.text)) return false;

      const initializer = resolveInitializer(expression.text);
      if (!initializer) return false;

      seen.add(expression.text);
      const result = isExpressionTainted(initializer, seen);
      seen.delete(expression.text);
      return result;
    }

    if (
      ts.isPropertyAccessExpression(expression) ||
      ts.isElementAccessExpression(expression) ||
      ts.isNonNullExpression(expression) ||
      ts.isParenthesizedExpression(expression) ||
      ts.isAsExpression(expression) ||
      ts.isTypeAssertionExpression(expression) ||
      ts.isAwaitExpression(expression)
    ) {
      return isExpressionTainted(expression.expression, seen);
    }

    if (ts.isBinaryExpression(expression)) {
      return isExpressionTainted(expression.left, seen) || isExpressionTainted(expression.right, seen);
    }

    if (ts.isConditionalExpression(expression)) {
      return (
        isExpressionTainted(expression.condition, seen) ||
        isExpressionTainted(expression.whenTrue, seen) ||
        isExpressionTainted(expression.whenFalse, seen)
      );
    }

    if (ts.isTemplateExpression(expression)) {
      return expression.templateSpans.some(span => isExpressionTainted(span.expression, seen));
    }

    if (ts.isTaggedTemplateExpression(expression)) {
      return isExpressionTainted(expression.template, seen);
    }

    if (ts.isCallExpression(expression)) {
      return expression.arguments.some(arg => isExpressionTainted(arg, seen));
    }

    if (ts.isObjectLiteralExpression(expression)) {
      return expression.properties.some(property => {
        if (ts.isSpreadAssignment(property)) return isExpressionTainted(property.expression, seen);
        if (ts.isPropertyAssignment(property)) return isExpressionTainted(property.initializer, seen);
        if (ts.isShorthandPropertyAssignment(property)) return isExpressionTainted(property.name, seen);
        return false;
      });
    }

    if (ts.isArrayLiteralExpression(expression)) {
      return expression.elements.some(element => isExpressionTainted(element, seen));
    }

    let tainted = false;
    expression.forEachChild(child => {
      if (!tainted && isExpressionTainted(child, seen)) tainted = true;
    });
    return tainted;
  };

  return { initialTaints, resolveInitializer, isExpressionTainted };
}

export function expressionReferencesNames(node: ts.Node | undefined, names: Set<string>): boolean {
  if (!node || names.size === 0) return false;

  let found = false;
  const visit = (child: ts.Node) => {
    if (found) return;
    if (ts.isIdentifier(child) && names.has(child.text)) {
      found = true;
      return;
    }
    ts.forEachChild(child, visit);
  };

  visit(node);
  return found;
}

export function getObjectPropertyInitializer(
  objectLiteral: ts.ObjectLiteralExpression,
  propertyName: string,
): ts.Expression | undefined {
  for (const property of objectLiteral.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    if (getPropertyName(property.name) === propertyName) return property.initializer;
  }

  return undefined;
}

export function getPropertyName(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)) return name.text;
  return undefined;
}

export function getNodeLine(sourceFile: ts.SourceFile, node: ts.Node): number {
  return sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
}

export function getNodeSnippet(sourceFile: ts.SourceFile, node: ts.Node): string {
  const text = node.getText(sourceFile).trim();
  return text.split(/\r?\n/).slice(0, 3).join('\n');
}

export function isPrismaWriteCall(call: ts.CallExpression, sourceFile: ts.SourceFile): boolean {
  const text = call.expression.getText(sourceFile);
  return /(?:^|\.)((?:prisma|tx))\./.test(text) && /\.(create|createMany|update|updateMany|upsert)$/.test(text);
}

export function isPrismaLookupCall(call: ts.CallExpression, sourceFile: ts.SourceFile): boolean {
  const text = call.expression.getText(sourceFile);
  return /(?:^|\.)((?:prisma|tx))\./.test(text) &&
    /\.(findFirst|findFirstOrThrow|findUnique|findUniqueOrThrow|update|delete|deleteMany|updateMany)$/.test(text);
}

export function isPrismaRawCall(call: ts.CallExpression, sourceFile: ts.SourceFile): boolean {
  const text = call.expression.getText(sourceFile);
  return /(?:^|\.)((?:prisma|tx))\.\$(queryRaw|executeRaw|queryRawUnsafe|executeRawUnsafe)$/.test(text);
}

export function isSafeTaggedPrismaRaw(node: ts.TaggedTemplateExpression, sourceFile: ts.SourceFile): boolean {
  const text = node.tag.getText(sourceFile);
  return /(?:^|\.)((?:prisma|tx))\.\$(queryRaw|executeRaw)$/.test(text);
}

function getBindingNames(binding: ts.BindingName): string[] {
  if (ts.isIdentifier(binding)) return [binding.text];

  const names: string[] = [];
  binding.elements.forEach(element => {
    if (ts.isBindingElement(element)) names.push(...getBindingNames(element.name));
  });
  return names;
}

function getDecoratorName(decorator: ts.Decorator): string | undefined {
  if (ts.isCallExpression(decorator.expression)) {
    const expression = decorator.expression.expression;
    if (ts.isIdentifier(expression)) return expression.text;
    if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
    return undefined;
  }

  if (ts.isIdentifier(decorator.expression)) return decorator.expression.text;
  return undefined;
}

function getParameterSourceKind(parameter: ts.ParameterDeclaration): InputSourceKind | undefined {
  for (const decorator of parameter.modifiers?.filter(ts.isDecorator) || []) {
    const name = getDecoratorName(decorator);
    if (name === 'Body') return 'body';
    if (name === 'Param') return 'param';
    if (name === 'Query') return 'query';
  }
  return undefined;
}

function getServiceCallInfo(call: ts.CallExpression): { methodName: string } | undefined {
  if (!ts.isPropertyAccessExpression(call.expression)) return undefined;

  const receiver = call.expression.expression.getText();
  if (!/service/i.test(receiver)) return undefined;

  return { methodName: call.expression.name.text };
}
