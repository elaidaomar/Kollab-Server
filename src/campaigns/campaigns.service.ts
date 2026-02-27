import {
    Injectable,
    NotFoundException,
    ForbiddenException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Campaign, CampaignStatus } from './entities/campaign.entity';
import { Application, ApplicationStatus } from './entities/application.entity';
import { CreateCampaignDto } from './dto/create-campaign.dto';
import { UpdateCampaignDto } from './dto/update-campaign.dto';
import { BrandProfile } from '../auth/entities/brand-profile.entity';
import { CreatorProfile } from '../auth/entities/creator-profile.entity';

@Injectable()
export class CampaignsService {
    constructor(
        @InjectRepository(Campaign)
        private campaignsRepository: Repository<Campaign>,
        @InjectRepository(Application)
        private applicationsRepository: Repository<Application>,
    ) { }

    async create(createCampaignDto: CreateCampaignDto, brand: BrandProfile) {
        const campaign = this.campaignsRepository.create({
            ...createCampaignDto,
            brand,
        });
        return this.campaignsRepository.save(campaign);
    }

    async findAll(status?: CampaignStatus) {
        const query = this.campaignsRepository
            .createQueryBuilder('campaign')
            .leftJoinAndSelect('campaign.brand', 'brand');

        if (status) {
            query.andWhere('campaign.status = :status', { status });
        }

        return query.getMany();
    }

    async findOne(id: string) {
        const campaign = await this.campaignsRepository.findOne({
            where: { id },
            relations: ['brand', 'applications', 'applications.creator'],
        });

        if (!campaign) {
            throw new NotFoundException(`Campaign with ID ${id} not found`);
        }

        return campaign;
    }

    async update(id: string, updateCampaignDto: UpdateCampaignDto, brandId: string) {
        const campaign = await this.findOne(id);

        if (campaign.brand.id !== brandId) {
            throw new ForbiddenException('You can only update your own campaigns');
        }

        Object.assign(campaign, updateCampaignDto);
        return this.campaignsRepository.save(campaign);
    }

    async apply(campaignId: string, creator: CreatorProfile, message?: string) {
        const campaign = await this.findOne(campaignId);

        if (campaign.status !== CampaignStatus.ACTIVE) {
            throw new ForbiddenException('You can only apply to active campaigns');
        }

        const existingApplication = await this.applicationsRepository.findOne({
            where: {
                campaign: { id: campaignId },
                creator: { id: creator.id },
            },
        });

        if (existingApplication) {
            throw new ForbiddenException('You have already applied to this campaign');
        }

        const application = this.applicationsRepository.create({
            campaign,
            creator,
            message,
        });

        return this.applicationsRepository.save(application);
    }

    async findByBrand(brandId: string) {
        return this.campaignsRepository.find({
            where: { brand: { id: brandId } },
            relations: ['applications'],
        });
    }
}
