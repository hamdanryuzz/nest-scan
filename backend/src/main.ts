import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable CORS for Next.js frontend
  app.enableCors({
    origin: ['http://localhost:3000', 'http://localhost:3001'],
    methods: ['GET', 'POST'],
    credentials: true,
  });

  const port = 4000;
  await app.listen(port);
  console.log(`🔍 NestJS Scanner API running on http://localhost:${port}`);
}
bootstrap();
