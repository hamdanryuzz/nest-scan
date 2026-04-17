import { Injectable, Logger } from '@nestjs/common';
import * as simpleGit from 'simple-git';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

@Injectable()
export class GitService {
  private readonly logger = new Logger(GitService.name);
  private readonly baseDir = path.join(os.tmpdir(), 'nest-scan-repos');

  constructor() {
    if (!fs.existsSync(this.baseDir)) {
      fs.mkdirSync(this.baseDir, { recursive: true });
    }
  }

  /**
   * Clone a repository to a temporary directory.
   * Returns the path to the cloned repo.
   */
  async cloneRepo(repoUrl: string, branch: string, pat?: string): Promise<string> {
    const repoId = `scan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const targetDir = path.join(this.baseDir, repoId);

    // Build authenticated URL if PAT provided
    let authUrl = repoUrl;
    if (pat) {
      try {
        const url = new URL(repoUrl);
        url.username = 'oauth2';
        url.password = pat;
        authUrl = url.toString();
      } catch {
        // If URL parsing fails, try the common GitHub format
        authUrl = repoUrl.replace('https://', `https://oauth2:${pat}@`);
      }
    }

    this.logger.log(`Cloning ${repoUrl} (branch: ${branch}) to ${targetDir}`);

    try {
      const git = simpleGit.simpleGit();
      await git.clone(authUrl, targetDir, [
        '--branch', branch,
        '--depth', '1',        // Shallow clone for speed
        '--single-branch',
      ]);

      this.logger.log(`Clone complete: ${targetDir}`);
      return targetDir;
    } catch (error: any) {
      this.logger.error(`Clone failed: ${error.message}`);

      // Clean up partial clone
      this.cleanup(targetDir);

      // Sanitize error message (don't expose PAT)
      const safeMessage = error.message
        .replace(/oauth2:[^@]+@/g, 'oauth2:***@')
        .replace(new RegExp(pat || 'NOPAT', 'g'), '***');

      throw new Error(`Git clone gagal: ${safeMessage}`);
    }
  }

  /**
   * Remove a cloned repository directory.
   */
  cleanup(repoPath: string): void {
    try {
      if (fs.existsSync(repoPath)) {
        fs.rmSync(repoPath, { recursive: true, force: true });
        this.logger.log(`Cleaned up: ${repoPath}`);
      }
    } catch (error: any) {
      this.logger.warn(`Cleanup failed for ${repoPath}: ${error.message}`);
    }
  }
}
