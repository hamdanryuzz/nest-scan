import { Finding } from '../models/report.model';
import * as path from 'path';

export function buildFindingContext(
  finding: Finding,
  fileContents: Map<string, string>,
): string {
  const fileContent = resolveFileContent(finding.file, fileContents);
  const sections: string[] = [
    `Finding ID: ${finding.id}`,
    `Analyzer: ${finding.analyzer}`,
    `Severity: ${finding.severity.toUpperCase()}`,
    `Confidence: ${finding.confidence.toUpperCase()} (${finding.confidenceScore}/100)`,
    `Location: ${finding.file}${finding.line ? `:${finding.line}` : ''}`,
    `Description: ${finding.description}`,
  ];

  if (finding.confidenceReason) {
    sections.push(`Rule Confidence Reason: ${finding.confidenceReason}`);
  }

  if (finding.aiValidation) {
    sections.push(
      `AI Validation: ${finding.aiValidation.verdict} (${finding.aiValidation.confidence}/100) - ${finding.aiValidation.rationale}`,
    );
  }

  if (finding.suggestion) {
    sections.push(`Scanner Suggestion: ${finding.suggestion}`);
  }

  if (fileContent) {
    const imports = extractImports(fileContent);
    if (imports) {
      sections.push(`Imports:\n\`\`\`typescript\n${imports}\n\`\`\``);
    }

    const surrounding = extractWindow(fileContent, finding.line || 1, 6, 10);
    sections.push(`Nearby Code:\n\`\`\`typescript\n${surrounding}\n\`\`\``);

    const enclosingBlock = extractEnclosingBlock(fileContent, finding.line || 1);
    if (enclosingBlock && enclosingBlock !== surrounding) {
      sections.push(`Enclosing Block:\n\`\`\`typescript\n${enclosingBlock}\n\`\`\``);
    }

    const relatedFiles = extractRelatedFiles(finding.file, fileContents);
    if (relatedFiles.length > 0) {
      sections.push(
        relatedFiles.map(related => {
          const relatedContent = extractFileSignature(related.content);
          return `Related File: ${related.path}\n\`\`\`typescript\n${relatedContent}\n\`\`\``;
        }).join('\n\n'),
      );
    }
  }

  return sections.join('\n\n');
}

function resolveFileContent(file: string, fileContents: Map<string, string>): string {
  return fileContents.get(file) || fileContents.get(`src/${file}`) || '';
}

function extractImports(content: string): string {
  const lines = content.split(/\r?\n/);
  return lines
    .filter(line => /^\s*import\s+/.test(line))
    .slice(0, 12)
    .join('\n')
    .trim();
}

function extractWindow(content: string, line: number, before: number, after: number): string {
  const lines = content.split(/\r?\n/);
  const start = Math.max(0, line - 1 - before);
  const end = Math.min(lines.length, line + after);
  return lines.slice(start, end)
    .map((text, index) => {
      const lineNum = start + index + 1;
      return `${lineNum}${lineNum === line ? ' ->' : '   '} ${text}`;
    })
    .join('\n')
    .trim();
}

function extractEnclosingBlock(content: string, line: number): string {
  const lines = content.split(/\r?\n/);
  const targetIndex = Math.max(0, Math.min(lines.length - 1, line - 1));

  let start = targetIndex;
  for (let i = targetIndex; i >= 0; i -= 1) {
    const current = lines[i];
    if (
      /^\s*@/.test(current) ||
      /^\s*(export\s+)?class\s+/.test(current) ||
      /^\s*(public|private|protected)?\s*(async\s+)?[A-Za-z0-9_]+\s*\([^)]*\)\s*[:{]/.test(current) ||
      /^\s*(if|for|while|switch)\s*\(/.test(current)
    ) {
      start = i;
      if (!/^\s*@/.test(current)) break;
    }
  }

  let depth = 0;
  let seenOpeningBrace = false;
  let end = Math.min(lines.length - 1, targetIndex + 12);

  for (let i = start; i < lines.length; i += 1) {
    const current = lines[i];
    const opens = (current.match(/\{/g) || []).length;
    const closes = (current.match(/\}/g) || []).length;
    if (opens > 0) seenOpeningBrace = true;
    depth += opens - closes;

    if (seenOpeningBrace && depth <= 0 && i >= targetIndex) {
      end = i;
      break;
    }
  }

  return lines.slice(start, end + 1).join('\n').trim();
}

function extractRelatedFiles(
  file: string,
  fileContents: Map<string, string>,
): Array<{ path: string; content: string }> {
  const normalized = file.replace(/\\/g, '/');
  const dir = path.posix.dirname(normalized);
  const currentBaseName = path.posix.basename(normalized);

  const priorities = [
    '.controller.ts',
    '.module.ts',
    '.service.ts',
    '.dto.ts',
  ];

  const candidates = Array.from(fileContents.entries())
    .map(([filePath, content]) => ({ path: filePath.replace(/\\/g, '/'), content }))
    .filter(entry =>
      entry.path !== normalized &&
      path.posix.dirname(entry.path) === dir &&
      priorities.some(suffix => entry.path.endsWith(suffix)) &&
      !entry.path.endsWith(currentBaseName),
    )
    .sort((a, b) => {
      const score = (value: string) => {
        const index = priorities.findIndex(suffix => value.endsWith(suffix));
        return index === -1 ? 99 : index;
      };
      return score(a.path) - score(b.path);
    })
    .slice(0, 2)
    .map(entry => ({
      path: entry.path,
      content: entry.content,
    }));

  return candidates;
}

function extractFileSignature(content: string): string {
  const lines = content.split(/\r?\n/);
  const important = lines.filter(line =>
    /^\s*import\s+/.test(line) ||
    /^\s*@/.test(line) ||
    /^\s*(export\s+)?class\s+/.test(line) ||
    /^\s*(public|private|protected)?\s*(async\s+)?[A-Za-z0-9_]+\s*\(/.test(line),
  );

  const source = important.length > 0 ? important : lines.slice(0, 20);
  return source.slice(0, 25).join('\n').trim();
}
