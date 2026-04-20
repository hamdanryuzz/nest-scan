import { Body, Controller, Post, HttpException, HttpStatus } from '@nestjs/common';
import { ScannerService } from './scanner.service';
import {
  AiFindingActionRequest,
  AiFindingActionResponse,
  ScanReport,
  ScanRequest,
} from './models/report.model';

@Controller('scanner')
export class ScannerController {
  constructor(private readonly scannerService: ScannerService) {}

  @Post('scan')
  async scan(@Body() body: ScanRequest): Promise<ScanReport> {
    if (!body.repoUrl || !body.branch) {
      throw new HttpException('repoUrl dan branch wajib diisi', HttpStatus.BAD_REQUEST);
    }
    if (!body.repoUrl.includes('github.com')) {
      throw new HttpException('Saat ini hanya support GitHub repository', HttpStatus.BAD_REQUEST);
    }
    try {
      return await this.scannerService.scan(body);
    } catch (error: any) {
      throw new HttpException(error.message || 'Scan gagal', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Post('ai-action')
  async runAiAction(@Body() body: AiFindingActionRequest): Promise<AiFindingActionResponse> {
    if (!body.reportId || !body.findingId || !body.action) {
      throw new HttpException('reportId, findingId, dan action wajib diisi', HttpStatus.BAD_REQUEST);
    }

    try {
      return await this.scannerService.runFindingAiAction(body);
    } catch (error: any) {
      throw new HttpException(error.message || 'AI action gagal', HttpStatus.BAD_REQUEST);
    }
  }
}
