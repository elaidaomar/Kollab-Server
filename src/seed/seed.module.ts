import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../auth/entities/user.entity';
import { BrandProfile } from '../auth/entities/brand-profile.entity';
import { CreatorProfile } from '../auth/entities/creator-profile.entity';
import { Campaign } from '../campaigns/entities/campaign.entity';
import { Application } from '../campaigns/entities/application.entity';
import { SeedService } from './seed.service';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      User,
      BrandProfile,
      CreatorProfile,
      Campaign,
      Application,
    ]),
    ConfigModule,
  ],
  providers: [SeedService],
  exports: [SeedService],
})
export class SeedModule { }
