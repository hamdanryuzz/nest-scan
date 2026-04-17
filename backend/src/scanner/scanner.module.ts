import { Module } from '@nestjs/common';
import { ScannerController } from './scanner.controller';
import { ScannerService } from './scanner.service';
import { GitHubApiService } from './git/github-api.service';
import { GemmaService } from './ai/gemma.service';

@Module({
  controllers: [ScannerController],
  providers: [ScannerService, GitHubApiService, GemmaService],
})
export class ScannerModule {}
