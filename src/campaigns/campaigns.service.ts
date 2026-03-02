import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Campaign, CampaignStatus } from './entities/campaign.entity';
import { Application, ApplicationStatus } from './entities/application.entity';
import { CreateCampaignDto } from './dto/create-campaign.dto';
import { UpdateCampaignDto } from './dto/update-campaign.dto';
import { User } from '../auth/entities/user.entity';

@Injectable()
export class CampaignsService {
  private readonly logger = new Logger(CampaignsService.name);

  constructor(
    @InjectRepository(Campaign)
    private campaignsRepository: Repository<Campaign>,
    @InjectRepository(Application)
    private applicationsRepository: Repository<Application>,
  ) { }

  async create(createCampaignDto: CreateCampaignDto, brand: User) {
    this.logger.log(`Creating campaign for brand userId=${brand.id}`);
    const campaign = this.campaignsRepository.create({
      ...createCampaignDto,
      brand,
    });
    const saved = await this.campaignsRepository.save(campaign);
    this.logger.log(`Created campaign ${saved.id} for brand userId=${brand.id}`);
    return saved;
  }

  async findAll(status?: CampaignStatus) {
    const query = this.campaignsRepository
      .createQueryBuilder('campaign')
      .leftJoinAndSelect('campaign.brand', 'brand');

    if (status) {
      query.andWhere('campaign.status = :status', { status });
    }

    const campaigns = await query.getMany();
    this.logger.log(`Found ${campaigns.length} campaigns`);
    return campaigns;
  }

  async findOne(id: string) {
    const campaign = await this.campaignsRepository.findOne({
      where: { id },
      relations: ['brand', 'applications', 'applications.creator'],
    });

    if (!campaign) {
      this.logger.warn(`Campaign ${id} not found`);
      throw new NotFoundException(`Campaign with ID ${id} not found`);
    }

    this.logger.log(`Found campaign ${id}`);
    return campaign;
  }

  async update(
    id: string,
    updateCampaignDto: UpdateCampaignDto,
    brandId: string,
  ) {
    this.logger.log(`Updating campaign ${id} for brand userId=${brandId}`);
    const campaign = await this.findOne(id);

    if (campaign.brand.id !== brandId) {
      this.logger.warn(
        `Forbidden: Brand userId=${brandId} attempted to update campaign ${id} belonging to userId=${campaign.brand.id}`,
      );
      throw new ForbiddenException('You can only update your own campaigns');
    }

    if (campaign.status === CampaignStatus.DELETED) {
      this.logger.warn(
        `Forbidden: Brand userId=${brandId} attempted to update deleted campaign ${id}`,
      );
      throw new ForbiddenException('You cannot update a deleted campaign');
    }

    Object.assign(campaign, updateCampaignDto);
    const updated = await this.campaignsRepository.save(campaign);
    this.logger.log(`Successfully updated campaign ${id}`);
    return updated;
  }

  async apply(campaignId: string, creator: User, message?: string) {
    this.logger.log(
      `Processing application from creator userId=${creator.id} for campaign ${campaignId}`,
    );
    const campaign = await this.findOne(campaignId);

    if (campaign.status !== CampaignStatus.ACTIVE) {
      this.logger.warn(
        `Forbidden: Creator userId=${creator.id} attempted to apply to inactive campaign ${campaignId}`,
      );
      throw new ForbiddenException('You can only apply to active campaigns');
    }

    const existingApplication = await this.applicationsRepository.findOne({
      where: {
        campaign: { id: campaignId },
        creator: { id: creator.id },
      },
    });

    if (existingApplication) {
      this.logger.warn(
        `Forbidden: Creator userId=${creator.id} already applied to campaign ${campaignId}`,
      );
      throw new ForbiddenException('You have already applied to this campaign');
    }

    const application = this.applicationsRepository.create({
      campaign,
      creator,
      message,
    });

    const saved = await this.applicationsRepository.save(application);
    this.logger.log(
      `Successfully created application ${saved.id} for creator userId=${creator.id} on campaign ${campaignId}`,
    );
    return saved;
  }

  async delete(id: string, brandId: string) {
    this.logger.log(`Deleting campaign ${id} for brand userId=${brandId}`);
    const campaign = await this.findOne(id);

    if (campaign.brand.id !== brandId) {
      this.logger.warn(
        `Forbidden: Brand userId=${brandId} attempted to delete campaign ${id} belonging to userId=${campaign.brand.id}`,
      );
      throw new ForbiddenException('You can only delete your own campaigns');
    }

    if (campaign.status === CampaignStatus.DELETED) {
      this.logger.warn(`Bad Request: Campaign ${id} is already deleted`);
      throw new ForbiddenException('Campaign is already deleted');
    }

    campaign.status = CampaignStatus.DELETED;
    const deleted = await this.campaignsRepository.save(campaign);
    this.logger.log(`Successfully soft-deleted campaign ${id}`);
    return deleted;
  }

  async findByBrand(brandId: string) {
    this.logger.log(`Fetching campaigns for brand userId=${brandId}`);
    const campaigns = await this.campaignsRepository.find({
      where: { brand: { id: brandId } },
      relations: ['applications'],
    });
    this.logger.log(`Found ${campaigns.length} campaigns for brand userId=${brandId}`);
    return campaigns;
  }

  async findMyApplications(creatorId: string) {
    this.logger.log(`Fetching applications for creator userId=${creatorId}`);
    const applications = await this.applicationsRepository.find({
      where: { creator: { id: creatorId } },
      relations: ['campaign', 'campaign.brand'],
    });
    this.logger.log(`Found ${applications.length} applications for creator userId=${creatorId}`);
    return applications;
  }
}
