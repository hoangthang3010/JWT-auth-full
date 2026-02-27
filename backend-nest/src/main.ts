import { NestFactory } from '@nestjs/core';
import { RequestMethod } from '@nestjs/common';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  app.setGlobalPrefix('api', {
    exclude: [
      { path: '', method: RequestMethod.GET },
      { path: 'health', method: RequestMethod.GET },
    ],
  });
  app.enableCors({
    origin: configService.get('CLIENT_URL') || true,
    credentials: true,
  });
  app.use(cookieParser());

  const port = configService.get('PORT') || 5001;
  await app.listen(port);
  console.log(`server bắt đầu trên cổng ${port}`);
}
bootstrap();
