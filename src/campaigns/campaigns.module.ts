import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CampaignsService } from './campaigns.service';
import { CampaignsController } from './campaigns.controller';
import { Campaign } from './entities/campaign.entity';
import { Application } from './entities/application.entity';
import { AuthModule } from '../auth/auth.module';
import { SeedModule } from '../seed/seed.module';

import { User } from '../auth/entities/user.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Campaign, Application, User]), SeedModule, AuthModule],
  controllers: [CampaignsController],
  providers: [CampaignsService],
  exports: [CampaignsService],
})
export class CampaignsModule { }
