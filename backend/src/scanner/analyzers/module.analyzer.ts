import { BaseAnalyzer } from './base.analyzer';
import { Finding, ModuleInfo } from '../models/report.model';
import * as fs from 'fs';
import * as path from 'path';

export class ModuleAnalyzer extends BaseAnalyzer {
  readonly name = 'module-completeness';
  readonly description = 'Checks if each NestJS module has all required files';

  public modules: ModuleInfo[] = [];

  async analyze(projectPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    this.modules = [];
    const srcPath = path.join(projectPath, 'src');
    if (!fs.existsSync(srcPath)) return findings;

    // Find all module directories (directories that contain a .module.ts, .controller.ts, or .service.ts)
    const moduleDirs = this.findModuleDirs(srcPath);

    for (const dir of moduleDirs) {
      const name = path.basename(dir);
      const files = fs.readdirSync(dir);

      const info: ModuleInfo = {
        name,
        path: path.relative(projectPath, dir).replace(/\\/g, '/'),
        hasController: files.some(f => f.endsWith('.controller.ts')),
        hasService: files.some(f => f.endsWith('.service.ts')),
        hasModule: files.some(f => f.endsWith('.module.ts')),
        hasDtoFolder: files.includes('dto') || files.some(f => f.endsWith('.dto.ts')),
        hasSpecFile: files.some(f => f.includes('.spec.ts')),
        controllerFile: files.find(f => f.endsWith('.controller.ts')),
        serviceFile: files.find(f => f.endsWith('.service.ts')),
        moduleFile: files.find(f => f.endsWith('.module.ts')),
      };

      this.modules.push(info);

      // Check completeness
      const missing: string[] = [];
      if (!info.hasController && info.hasService) missing.push('controller');
      if (!info.hasService && info.hasController) missing.push('service');
      if (!info.hasModule) missing.push('module file');
      if (info.hasController && !info.hasDtoFolder) missing.push('dto folder');

      if (missing.length > 0) {
        findings.push(this.createFinding('info',
          `Module "${name}" — missing: ${missing.join(', ')}`,
          `Module ini tidak lengkap. Missing: ${missing.join(', ')}.`,
          dir, projectPath));
      }

      if (!info.hasSpecFile && info.hasService) {
        findings.push(this.createFinding('info',
          `Module "${name}" — tidak ada test file`,
          `Service di module ini belum punya unit test (.spec.ts).`,
          dir, projectPath,
          { suggestion: `Buat file ${name}.service.spec.ts untuk unit test.` }));
      }
    }

    return findings;
  }

  private findModuleDirs(dir: string): string[] {
    const results: string[] = [];
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      const hasNestFile = entries.some(e =>
        e.isFile() && (e.name.endsWith('.controller.ts') || e.name.endsWith('.service.ts') || e.name.endsWith('.module.ts')));

      if (hasNestFile) results.push(dir);

      for (const entry of entries) {
        if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== 'dist') {
          results.push(...this.findModuleDirs(path.join(dir, entry.name)));
        }
      }
    } catch {}
    return results;
  }
}
