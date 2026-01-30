import { NestFactory } from '@nestjs/core'
import { ValidationPipe } from '@nestjs/common'
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger'
import { AppModule } from './app.module'
import { ConfigService } from '@nestjs/config'
import cookieParser from 'cookie-parser'

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    snapshot: true,
  })

  app.use(cookieParser())

  const configService = app.get(ConfigService)
  const port = configService.get<number>('PORT') || 3001
  const corsOrigin = configService.get<string>('CORS_ORIGIN') || 'http://localhost:3000'

  app.enableCors({
    origin: corsOrigin,
    credentials: true,
  })

  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }))

  // Build Swagger config
  const config = new DocumentBuilder()
    .setTitle('Kollab API')
    .setDescription('This is the Kollab API documentation')
    .setVersion('1.0')
    .addBearerAuth() // <- JWT auth for protected endpoints
    .build()

  // Create document including all modules (AppModule and its imports)
  const document = SwaggerModule.createDocument(app, config)

  // Setup Swagger route
  SwaggerModule.setup('api', app, document)

  await app.listen(port)
}
bootstrap()
