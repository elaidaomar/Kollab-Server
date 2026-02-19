import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../auth/entities/user.entity';
import { UserRole } from '../auth/enums/role.enum';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';

@Injectable()
export class SeedService {
  private readonly logger = new Logger(SeedService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private configService: ConfigService,
  ) {}

  async seedAdmin() {
    const adminEmail =
      this.configService.get<string>('ADMIN_EMAIL') || 'elaidaomar@gmail.com';
    const adminPassword =
      this.configService.get<string>('ADMIN_PASSWORD') || 'adminomar!';

    const existingAdmin = await this.userRepository.findOne({
      where: { email: adminEmail, role: UserRole.ADMIN },
    });

    if (!existingAdmin) {
      this.logger.log('Seeding initial admin user...');
      const rounds = Number(this.configService.get('BCRYPT_SALT_ROUNDS')) || 12;
      const hashedPassword = await bcrypt.hash(adminPassword, rounds);

      await this.userRepository.save({
        email: adminEmail,
        password: hashedPassword,
        name: 'Omar',
        surname: 'Elaida',
        role: UserRole.ADMIN,
        isEmailVerified: true,
        isAdminApproved: true,
      });
      this.logger.log(
        `Initial admin user (${adminEmail}) seeded successfully.`,
      );
    } else {
      this.logger.log('Admin user already exists.');
    }
  }
}
