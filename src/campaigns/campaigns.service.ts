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
import { UserRole } from '../auth/enums/role.enum';
import { MailService } from '../auth/mail.service';

@Injectable()
export class CampaignsService {
  private readonly logger = new Logger(CampaignsService.name);

  constructor(
    @InjectRepository(Campaign)
    private campaignsRepository: Repository<Campaign>,
    @InjectRepository(Application)
    private applicationsRepository: Repository<Application>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private readonly mailService: MailService,
  ) { }

  async create(createCampaignDto: CreateCampaignDto, brand: User) {
    this.logger.log(`Creating campaign for brand userId=${brand.id}`);
    const campaign = this.campaignsRepository.create({
      ...createCampaignDto,
      brand,
    });
    const saved = await this.campaignsRepository.save(campaign);
    this.logger.log(`Created campaign ${saved.id} for brand userId=${brand.id}`);

    // Fetch with profiles for pruning
    const fresh = await this.campaignsRepository.findOne({
      where: { id: saved.id },
      relations: ['brand', 'brand.brandProfile']
    });
    return this.pruneCampaign(fresh!);
  }

  async findAll(status?: CampaignStatus) {
    const query = this.campaignsRepository
      .createQueryBuilder('campaign')
      .leftJoinAndSelect('campaign.brand', 'brand')
      .leftJoinAndSelect('brand.brandProfile', 'brandProfile');

    if (status) {
      query.andWhere('campaign.status = :status', { status });
    }

    const campaigns = await query.getMany();
    this.logger.log(`Found ${campaigns.length} campaigns`);

    // Prune brand info
    return campaigns.map((campaign) => this.pruneCampaign(campaign));
  }

  private pruneCampaign(campaign: Campaign, applications: Application[] = []) {
    return {
      ...campaign,
      brand: campaign.brand
        ? {
          id: campaign.brand.id,
          name: campaign.brand.name,
          surname: campaign.brand.surname,
          company: campaign.brand.brandProfile?.company,
        }
        : null,
      applications: applications.map((app) => ({
        id: app.id,
        status: app.status,
        message: app.message,
        createdAt: app.createdAt,
        updatedAt: app.updatedAt,
        creator: app.creator
          ? {
            id: app.creator.id,
            name: app.creator.name,
            surname: app.creator.surname,
            handle: app.creator.creatorProfile?.handle,
          }
          : null,
      })),
    };
  }

  private async findOneInternal(id: string) {
    const campaign = await this.campaignsRepository.findOne({
      where: { id },
      relations: ['brand'],
    });

    if (!campaign) {
      this.logger.warn(`Campaign ${id} not found`);
      throw new NotFoundException(`Campaign with ID ${id} not found`);
    }
    return campaign;
  }

  async findOne(id: string, requester?: { id: string; role: string }) {
    this.logger.debug(`findOne called for campaign ${id} by user ${requester?.id}`);
    const campaign = await this.campaignsRepository.findOne({
      where: { id },
      relations: ['brand', 'brand.brandProfile'],
    });

    if (!campaign) {
      this.logger.warn(`Campaign ${id} not found`);
      throw new NotFoundException(`Campaign with ID ${id} not found`);
    }

    // Security: Filter applications based on requester
    let applications: Application[] = [];
    if (requester) {
      if (requester.role === 'brand' && campaign.brand.id === requester.id) {
        // Brand owner sees all applications
        applications = await this.applicationsRepository.find({
          where: { campaign: { id } },
          relations: ['creator', 'creator.creatorProfile'],
        });
      } else if (requester.role === 'creator') {
        // Creator sees only their own application
        const myApp = await this.applicationsRepository.findOne({
          where: { campaign: { id }, creator: { id: requester.id } },
          relations: ['creator', 'creator.creatorProfile'],
        });
        if (myApp) applications = [myApp];
      }
    }

    this.logger.log(`Found campaign ${id}`);

    // Return pruned campaign object
    return this.pruneCampaign(campaign, applications);
  }

  async update(
    id: string,
    updateCampaignDto: UpdateCampaignDto,
    brandId: string,
  ) {
    this.logger.log(`Updating campaign ${id} for brand userId=${brandId}`);
    const campaign = await this.findOneInternal(id);

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

    // Fetch with profiles for pruning
    const fresh = await this.campaignsRepository.findOne({
      where: { id: updated.id },
      relations: ['brand', 'brand.brandProfile']
    });
    return this.pruneCampaign(fresh!);
  }

  async apply(campaignId: string, creator: User, message?: string) {
    this.logger.log(
      `Processing application from creator userId=${creator.id} for campaign ${campaignId}`,
    );
    const campaign = await this.findOneInternal(campaignId);

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

    // Fetch with relations for pruning
    const fresh = await this.applicationsRepository.findOne({
      where: { id: saved.id },
      relations: ['creator', 'creator.creatorProfile', 'campaign', 'campaign.brand', 'campaign.brand.brandProfile']
    });
    return this.pruneApplication(fresh!);
  }

  async delete(id: string, brandId: string) {
    this.logger.log(`Deleting campaign ${id} for brand userId=${brandId}`);
    const campaign = await this.findOneInternal(id);

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

  private pruneApplication(app: Application) {
    return {
      id: app.id,
      status: app.status,
      message: app.message,
      createdAt: app.createdAt,
      updatedAt: app.updatedAt,
      creator: app.creator
        ? {
          id: app.creator.id,
          name: app.creator.name,
          surname: app.creator.surname,
          handle: app.creator.creatorProfile?.handle,
        }
        : null,
      campaign: app.campaign ? this.internalPruneCampaign(app.campaign) : null,
    };
  }

  private internalPruneCampaign(campaign: Campaign) {
    return {
      id: campaign.id,
      title: campaign.title,
      type: campaign.type,
      status: campaign.status,
      deadline: campaign.deadline,
      brand: campaign.brand
        ? {
          id: campaign.brand.id,
          name: campaign.brand.name,
          surname: campaign.brand.surname,
          company: campaign.brand.brandProfile?.company,
        }
        : null,
    };
  }

  async findByBrand(brandId: string) {
    this.logger.log(`Fetching campaigns for brand userId=${brandId}`);
    const campaigns = await this.campaignsRepository.find({
      where: { brand: { id: brandId } },
      relations: ['applications', 'applications.creator', 'applications.creator.creatorProfile', 'brand', 'brand.brandProfile'],
    });
    this.logger.log(`Found ${campaigns.length} campaigns for brand userId=${brandId}`);
    return campaigns.map((c) => this.pruneCampaign(c, c.applications));
  }

  async findMyApplications(creatorId: string) {
    this.logger.log(`Fetching applications for creator userId=${creatorId}`);
    const applications = await this.applicationsRepository.find({
      where: { creator: { id: creatorId } },
      relations: ['campaign', 'campaign.brand', 'campaign.brand.brandProfile'],
    });
    this.logger.log(`Found ${applications.length} applications for creator userId=${creatorId}`);
    return applications.map((app) => this.pruneApplication(app));
  }

  async updateApplicationStatus(id: string, status: ApplicationStatus, brandId: string) {
    this.logger.log(`Updating application ${id} status to ${status} by brand userId=${brandId}`);

    // Find application with creator, campaign and brand relations
    const application = await this.applicationsRepository.findOne({
      where: { id },
      relations: ['creator', 'creator.creatorProfile', 'campaign', 'campaign.brand', 'campaign.brand.brandProfile'],
    });

    if (!application) {
      this.logger.warn(`Application ${id} not found`);
      throw new NotFoundException(`Application with ID ${id} not found`);
    }

    // Security: Only the brand owner of the campaign can update the status
    if (application.campaign.brand.id !== brandId) {
      this.logger.warn(`Forbidden: Brand userId=${brandId} tried to update app ${id} of campaign owned by ${application.campaign.brand.id}`);
      throw new ForbiddenException('You can only update applications for your own campaigns');
    }

    application.status = status;
    const updated = await this.applicationsRepository.save(application);
    this.logger.log(`Successfully updated application ${id} to ${status}`);

    // Send email notification to the creator
    try {
      if (status === ApplicationStatus.ACCEPTED) {
        await this.mailService.sendApplicationAcceptedEmail(application.creator, application.campaign.title);
      } else if (status === ApplicationStatus.REJECTED) {
        await this.mailService.sendApplicationRejectedEmail(application.creator, application.campaign.title);
      }
    } catch (error) {
      this.logger.error(`Failed to send application ${status} email to ${application.creator.email}: ${error.message}`);
    }

    return this.pruneApplication(updated);
  }

  async findCreators(search?: string) {
    this.logger.log('Fetching approved creators for brand discovery');
    const query = this.userRepository
      .createQueryBuilder('user')
      .leftJoinAndSelect('user.creatorProfile', 'creatorProfile')
      .leftJoinAndSelect('user.applications', 'applications')
      .where('user.role = :role', { role: UserRole.CREATOR })
      .andWhere('user.isAdminApproved = :approved', { approved: true })
      .orderBy('user.createdAt', 'DESC');

    if (search) {
      query.andWhere(
        '(LOWER(user.name) LIKE :search OR LOWER(user.surname) LIKE :search OR LOWER(creatorProfile.handle) LIKE :search)',
        { search: `%${search.toLowerCase()}%` },
      );
    }

    const creators = await query.getMany();
    this.logger.log(`Found ${creators.length} creators`);

    return creators.map((creator) => ({
      id: creator.id,
      name: creator.name,
      surname: creator.surname,
      handle: creator.creatorProfile?.handle,
      applicationCount: creator.applications?.length ?? 0,
      joinedAt: creator.createdAt,
    }));
  }
}
