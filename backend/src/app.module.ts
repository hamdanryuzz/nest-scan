import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ScannerModule } from './scanner/scanner.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    ScannerModule,
  ],
})
export class AppModule {}
