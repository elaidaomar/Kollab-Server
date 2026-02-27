import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../auth/entities/user.entity';
import { UserRole } from '../auth/enums/role.enum';
import { BrandProfile } from '../auth/entities/brand-profile.entity';
import {
  Campaign,
  CampaignType,
  CampaignStatus,
} from '../campaigns/entities/campaign.entity';
import { Application } from '../campaigns/entities/application.entity';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class SeedService {
  private readonly logger = new Logger(SeedService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(BrandProfile)
    private brandRepository: Repository<BrandProfile>,
    @InjectRepository(Campaign)
    private campaignRepository: Repository<Campaign>,
    @InjectRepository(Application)
    private applicationRepository: Repository<Application>,
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

  async cleanCampaigns() {
    this.logger.log('Cleaning all campaigns and applications...');
    await this.applicationRepository.delete({});
    await this.campaignRepository.delete({});
    this.logger.log('All campaigns and applications cleared.');
  }

  async seedCampaigns() {
    this.logger.log('Seeding 5 test campaigns...');

    // Find or create a brand profile to assign campaigns to
    let brand = await this.brandRepository.findOne({ relations: ['user'] });

    if (!brand) {
      this.logger.log('No brand found, creating a test brand profile...');
      const user = await this.userRepository.save({
        email: `brand_${Date.now()}@test.com`,
        password: await bcrypt.hash('password123', 12),
        name: 'Test',
        surname: 'Brand',
        role: UserRole.BRAND,
        isEmailVerified: true,
        isAdminApproved: true,
      });
      brand = await this.brandRepository.save({
        company: 'Kollab Ventures',
        user: user,
      });
    }

    const testCampaigns = [
      {
        title: 'Summer Fashion Lookbook',
        summary: 'Create high-quality UGC for our new summer collection.',
        type: CampaignType.UGC,
        deadline: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
        brief:
          'We are looking for creators to showcase our new summer line in a natural setting. Focus on lifestyle shots.',
        dos: 'Natural lighting\nClear product visibility\nAuthentic enthusiasm',
        donts:
          'Harsh artificial light\nCompetitor products in frame\nOver-editing',
        paymentDetails: {
          totalEarnings: 500,
          breakdown: '$400 flat fee + $100 performance bonus',
        },
        creatorCriteria: {
          locations: ['Lagos', 'Abuja'],
          gender: 'Female',
          ageRange: '18-35',
        },
        followerCriteria: { minFollowers: 5000 },
        status: CampaignStatus.ACTIVE,
      },
      {
        title: 'Tech Gadget Review',
        summary:
          'Review our latest minimalist keyboard on your social channels.',
        type: CampaignType.SOCIAL,
        deadline: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000),
        brief:
          'Tell your audience about your experience using our keyboard for work. Highlight the mechanical switches.',
        dos: 'Sound tests\nClose-up hardware shots\nLink in bio',
        donts:
          'Comparisons to Top-tier brands\nBlurred backgrounds\nMuffled audio',
        paymentDetails: {
          totalEarnings: 300,
          breakdown: '$300 flat fee + Free Product',
        },
        creatorCriteria: {
          locations: ['Global'],
          gender: 'Any',
          ageRange: '20-45',
        },
        followerCriteria: { minFollowers: 10000 },
        status: CampaignStatus.ACTIVE,
      },
      {
        title: 'Organic Skincare Routine',
        summary: 'Show your morning skincare routine using our organic serum.',
        type: CampaignType.UGC,
        deadline: new Date(Date.now() + 21 * 24 * 60 * 60 * 1000),
        brief:
          'A 60-second video showing the application and immediate glow effect.',
        dos: 'Bare face before/after\nClean bathroom aesthetic\nNatural light',
        donts:
          'Filters\nHeavy makeup\nVoiceover only (we want to see you talking)',
        paymentDetails: { totalEarnings: 450, breakdown: '$450 flat fee' },
        creatorCriteria: {
          locations: ['London', 'New York'],
          gender: 'Female',
          ageRange: '25-40',
        },
        followerCriteria: { minFollowers: 25000 },
        status: CampaignStatus.ACTIVE,
      },
      {
        title: 'Fitness App Challenge',
        summary: 'Promote our 30-day fitness challenge on Instagram Reels.',
        type: CampaignType.SOCIAL,
        deadline: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        brief:
          'Encourage your followers to join the challenge. Show your first day workout.',
        dos: 'Workout motivation\nApp screen recording\nDiscount code mention',
        donts: 'Couch footage\nLong intros\nStock music',
        paymentDetails: {
          totalEarnings: 200,
          breakdown: '$150 flat + $50 per sign-up (capped at $200 bonus)',
        },
        creatorCriteria: {
          locations: ['Global'],
          gender: 'Any',
          ageRange: '18-35',
        },
        followerCriteria: { minFollowers: 2000 },
        status: CampaignStatus.ACTIVE,
      },
      {
        title: 'Coffee Aficionado Content',
        summary: 'Brewing techniques featuring our micro-lot beans.',
        type: CampaignType.UGC,
        deadline: new Date(Date.now() + 45 * 24 * 60 * 60 * 1000),
        brief: 'Cinematic shots of the brewing process. Slow motion preferred.',
        dos: 'Aesthetic props\nSteam shots\nJazz background music',
        donts: 'Dirty kitchen\nInstant coffee references\nPoor lighting',
        paymentDetails: { totalEarnings: 600, breakdown: '$600 for 3 videos' },
        creatorCriteria: {
          locations: ['USA', 'Europe'],
          gender: 'Any',
          ageRange: '22-50',
        },
        followerCriteria: { minFollowers: 15000 },
        status: CampaignStatus.ACTIVE,
      },
    ];

    for (const campaignData of testCampaigns) {
      await this.campaignRepository.save({
        ...campaignData,
        brand: brand,
      });
    }

    this.logger.log('5 Campaigns seeded successfully.');
  }
}
