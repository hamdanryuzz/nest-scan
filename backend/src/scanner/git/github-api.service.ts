import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';

export interface RepoFile {
  path: string;
  content: string;
  size: number;
}

@Injectable()
export class GitHubApiService {
  private readonly logger = new Logger(GitHubApiService.name);
  private readonly API = 'https://api.github.com';

  /**
   * Parse a GitHub URL into owner/repo.
   * Supports: https://github.com/owner/repo.git, https://github.com/owner/repo
   */
  parseRepoUrl(url: string): { owner: string; repo: string } {
    const m = url.match(/github\.com[/:]([^/]+)\/([^/.]+)/);
    if (!m) throw new Error('URL bukan format GitHub yang valid');
    return { owner: m[1], repo: m[2] };
  }

  private headers(pat?: string) {
    const h: Record<string, string> = {
      Accept: 'application/vnd.github.v3+json',
      'User-Agent': 'nest-scanner',
    };
    if (pat) h.Authorization = `Bearer ${pat}`;
    return h;
  }

  /**
   * Get the full file tree of a repo branch.
   */
  async getFileTree(owner: string, repo: string, branch: string, pat?: string): Promise<string[]> {
    const url = `${this.API}/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`;
    this.logger.log(`Fetching tree: ${owner}/${repo}@${branch}`);

    try {
      const res = await axios.get(url, { headers: this.headers(pat) });
      const tree = res.data.tree || [];
      return tree
        .filter((t: any) => t.type === 'blob')
        .map((t: any) => t.path);
    } catch (err: any) {
      const status = err.response?.status;
      if (status === 404) throw new Error(`Repo atau branch tidak ditemukan: ${owner}/${repo}@${branch}`);
      if (status === 403) throw new Error('Rate limit GitHub terlampaui. Coba tambahkan PAT.');
      if (status === 401) throw new Error('PAT tidak valid atau expired.');
      throw new Error(`GitHub API error: ${err.message}`);
    }
  }

  /**
   * Fetch content of a single file.
   */
  async getFileContent(owner: string, repo: string, path: string, branch: string, pat?: string): Promise<string> {
    const url = `${this.API}/repos/${owner}/${repo}/contents/${path}?ref=${branch}`;
    try {
      const res = await axios.get(url, { headers: this.headers(pat) });
      if (res.data.encoding === 'base64') {
        return Buffer.from(res.data.content, 'base64').toString('utf-8');
      }
      return res.data.content || '';
    } catch {
      return '';
    }
  }

  /**
   * Fetch all TypeScript files + Prisma schema from a repo.
   * Batches requests to stay within rate limits.
   */
  async fetchProjectFiles(
    owner: string, repo: string, branch: string, pat?: string,
  ): Promise<RepoFile[]> {
    const allPaths = await this.getFileTree(owner, repo, branch, pat);

    // Filter only relevant files
    const relevantPaths = allPaths.filter(p =>
      (p.startsWith('src/') || p === 'prisma/schema.prisma' || p === '.env' || p === '.gitignore') &&
      (p.endsWith('.ts') || p.endsWith('.prisma') || p === '.env' || p === '.gitignore') &&
      !p.includes('node_modules') && !p.includes('.spec.ts') && !p.includes('.test.ts') &&
      !p.includes('dist/'),
    );

    // Also include spec files for module completeness check
    const specPaths = allPaths.filter(p => p.endsWith('.spec.ts'));

    const filesToFetch = [...relevantPaths];
    this.logger.log(`Fetching ${filesToFetch.length} files (+ ${specPaths.length} spec files detected)`);

    // Fetch files in parallel batches of 10
    const files: RepoFile[] = [];
    const BATCH_SIZE = 10;

    for (let i = 0; i < filesToFetch.length; i += BATCH_SIZE) {
      const batch = filesToFetch.slice(i, i + BATCH_SIZE);
      const results = await Promise.all(
        batch.map(async (p) => {
          const content = await this.getFileContent(owner, repo, p, branch, pat);
          return { path: p, content, size: content.length };
        }),
      );
      files.push(...results.filter(f => f.content.length > 0));
    }

    this.logger.log(`Fetched ${files.length} files successfully`);
    return files;
  }
}
