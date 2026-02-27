import { NestFactory } from '@nestjs/core';
import { Logger } from '@nestjs/common';
import { AppModule } from './app.module';
import { SeedService } from './seed/seed.service';

async function bootstrap() {
  const logger = new Logger('Seeder');
  logger.log('Starting seeding process...');

  try {
    const app = await NestFactory.createApplicationContext(AppModule);
    const seeder = app.get(SeedService);

    await seeder.seedAdmin();
    // Only automatically clear/seed if needed, or keeping it for now as requested.
    await seeder.cleanCampaigns();
    await seeder.seedCampaigns();

    await app.close();
    logger.log('Seeding completed successfully.');
    process.exit(0);
  } catch (error) {
    logger.error('Seeding failed:', error);
    process.exit(1);
  }
}

bootstrap();
