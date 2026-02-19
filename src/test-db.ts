import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from './auth/entities/user.entity';
import { Repository } from 'typeorm';

async function bootstrap() {
  const app = await NestFactory.createApplicationContext(AppModule);
  const userRepository = app.get<Repository<User>>(getRepositoryToken(User));

  try {
    console.log('--- DB TEST START ---');
    const count = await userRepository.count();
    console.log('Total users in DB:', count);

    const users = await userRepository.find({
      take: 5,
    });
    console.log(
      'First 5 users IDs:',
      users.map((u) => u.id),
    );
    console.log('--- DB TEST END ---');
  } catch (e) {
    console.error('DB TEST FAILED:', e);
  } finally {
    await app.close();
  }
}
bootstrap();
