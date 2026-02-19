import { NestFactory } from '@nestjs/core';
import { SeedModule } from './seed/seed.module';
import { SeedService } from './seed/seed.service';
import { Logger } from '@nestjs/common';
import { AppModule } from './app.module';

async function bootstrap() {
    const logger = new Logger('Seeder');
    logger.log('Starting seeding process...');

    try {
        // Create a standalone application context
        const app = await NestFactory.createApplicationContext(AppModule);
        const seeder = app.get(SeedService);

        await seeder.seedAdmin();

        await app.close();
        logger.log('Seeding completed successfully.');
        process.exit(0);
    } catch (error) {
        logger.error('Seeding failed:', error);
        process.exit(1);
    }
}

bootstrap();
