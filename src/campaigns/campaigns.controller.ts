import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Delete,
  Param,
  UseGuards,
  Req,
  Query,
  Logger,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiResponse,
  ApiQuery,
} from '@nestjs/swagger';
import { CampaignsService } from './campaigns.service';
import { CreateCampaignDto } from './dto/create-campaign.dto';
import { UpdateCampaignDto } from './dto/update-campaign.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '../auth/enums/role.enum';
import { CampaignStatus } from './entities/campaign.entity';
import { ApprovedGuard } from '../auth/guards/approved.guard';
import { EmailVerifiedGuard } from '../auth/guards/email-verified.guard';
import { Application } from './entities/application.entity';

@ApiTags('Campaigns')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, ApprovedGuard, EmailVerifiedGuard, RolesGuard)
@Controller('campaigns')
export class CampaignsController {
  private readonly logger = new Logger(CampaignsController.name);

  constructor(private readonly campaignsService: CampaignsService) {}

  @Post()
  @Roles(UserRole.BRAND)
  @ApiOperation({ summary: 'Create a new campaign' })
  async create(@Body() createCampaignDto: CreateCampaignDto, @Req() req: any) {
    this.logger.log(
      `Brand ${req.user.brandProfile.id} creating a new campaign`,
    );
    return this.campaignsService.create(
      createCampaignDto,
      req.user.brandProfile,
    );
  }

  @Get()
  @ApiQuery({ name: 'status', required: false })
  @ApiOperation({ summary: 'Get all campaigns' })
  async findAll(@Query('status') status?: CampaignStatus) {
    this.logger.log(
      `Fetching all campaigns${status ? ` with status ${status}` : ''}`,
    );
    return this.campaignsService.findAll(status);
  }

  @Get('my-campaigns')
  @Roles(UserRole.BRAND)
  @ApiOperation({ summary: 'Get current brand campaigns' })
  async findMyCampaigns(@Req() req: any) {
    this.logger.log(`Fetching campaigns for brand ${req.user.brandProfile.id}`);
    return this.campaignsService.findByBrand(req.user.brandProfile.id);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get campaign by ID' })
  async findOne(@Param('id') id: string) {
    this.logger.log(`Fetching campaign ${id}`);
    return this.campaignsService.findOne(id);
  }

  @Patch(':id')
  @Roles(UserRole.BRAND)
  @ApiOperation({ summary: 'Update campaign' })
  async update(
    @Param('id') id: string,
    @Body() updateCampaignDto: UpdateCampaignDto,
    @Req() req: any,
  ) {
    this.logger.log(
      `Brand ${req.user.brandProfile.id} updating campaign ${id}`,
    );
    return this.campaignsService.update(
      id,
      updateCampaignDto,
      req.user.brandProfile.id,
    );
  }

  @Delete(':id')
  @Roles(UserRole.BRAND)
  @ApiOperation({ summary: 'Soft delete campaign' })
  async delete(@Param('id') id: string, @Req() req: any) {
    this.logger.log(
      `Brand ${req.user.brandProfile.id} deleting campaign ${id}`,
    );
    return this.campaignsService.delete(id, req.user.brandProfile.id);
  }

  @Post(':id/apply')
  @Roles(UserRole.CREATOR)
  @ApiOperation({ summary: 'Apply to a campaign' })
  async apply(
    @Param('id') id: string,
    @Body('message') message: string,
    @Req() req: any,
  ) {
    this.logger.log(
      `Creator ${req.user.creatorProfile.id} applying to campaign ${id}`,
    );
    return this.campaignsService.apply(id, req.user.creatorProfile, message);
  }
}
