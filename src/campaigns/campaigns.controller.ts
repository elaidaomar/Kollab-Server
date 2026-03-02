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
import { ApplicationStatus } from './entities/application.entity';
import { ApprovedGuard } from '../auth/guards/approved.guard';
import { EmailVerifiedGuard } from '../auth/guards/email-verified.guard';

@ApiTags('Campaigns')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, ApprovedGuard, EmailVerifiedGuard, RolesGuard)
@Controller('campaigns')
export class CampaignsController {
  private readonly logger = new Logger(CampaignsController.name);

  constructor(private readonly campaignsService: CampaignsService) { }

  // 1. LITERAL ROUTES FIRST
  @Get('creators')
  @Roles(UserRole.BRAND)
  @ApiQuery({ name: 'search', required: false })
  @ApiOperation({ summary: 'Browse approved creators (brand only)' })
  async findCreators(@Query('search') search?: string) {
    this.logger.log(`Fetching creators for brand discovery${search ? ` with search="${search}"` : ''}`);
    return this.campaignsService.findCreators(search);
  }

  @Get('my-campaigns')
  @Roles(UserRole.BRAND)
  @ApiOperation({ summary: 'Get current brand campaigns' })
  async findMyCampaigns(@Req() req: any) {
    this.logger.log(`Fetching campaigns for brand userId=${req.user.id}`);
    return this.campaignsService.findByBrand(req.user.id);
  }

  @Get('my-applications')
  @Roles(UserRole.CREATOR)
  @ApiOperation({ summary: 'Get current creator applications' })
  async findMyApplications(@Req() req: any) {
    this.logger.log(`Fetching applications for creator userId=${req.user.id}`);
    return this.campaignsService.findMyApplications(req.user.id);
  }

  // 2. GENERAL ROUTES
  @Get()
  @ApiQuery({ name: 'status', required: false })
  @ApiOperation({ summary: 'Get all campaigns' })
  async findAll(@Query('status') status?: CampaignStatus) {
    this.logger.log(`Fetching all campaigns${status ? ` with status ${status}` : ''}`);
    return this.campaignsService.findAll(status);
  }

  // 3. PARAMETER ROUTES LAST
  @Get(':id')
  @ApiOperation({ summary: 'Get campaign by ID' })
  async findOne(@Param('id') id: string, @Req() req: any) {
    this.logger.log(`Fetching campaign ${id}`);
    return this.campaignsService.findOne(id, { id: req.user.id, role: req.user.role });
  }

  @Post()
  @Roles(UserRole.BRAND)
  @ApiOperation({ summary: 'Create a new campaign' })
  async create(@Body() createCampaignDto: CreateCampaignDto, @Req() req: any) {
    this.logger.log(`Brand userId=${req.user.id} creating a new campaign`);
    return this.campaignsService.create(createCampaignDto, req.user);
  }

  @Patch('applications/:id/status')
  @Roles(UserRole.BRAND)
  @ApiOperation({ summary: 'Update application status (Approve/Decline)' })
  async updateApplicationStatus(
    @Param('id') id: string,
    @Body('status') status: ApplicationStatus,
    @Req() req: any,
  ) {
    this.logger.log(`Brand userId=${req.user.id} updating application ${id} status to ${status}`);
    return this.campaignsService.updateApplicationStatus(id, status, req.user.id);
  }

  @Patch(':id')
  @Roles(UserRole.BRAND)
  @ApiOperation({ summary: 'Update campaign' })
  async update(
    @Param('id') id: string,
    @Body() updateCampaignDto: UpdateCampaignDto,
    @Req() req: any,
  ) {
    this.logger.log(`Brand userId=${req.user.id} updating campaign ${id}`);
    return this.campaignsService.update(id, updateCampaignDto, req.user.id);
  }

  @Delete(':id')
  @Roles(UserRole.BRAND)
  @ApiOperation({ summary: 'Soft delete campaign' })
  async delete(@Param('id') id: string, @Req() req: any) {
    this.logger.log(`Brand userId=${req.user.id} deleting campaign ${id}`);
    return this.campaignsService.delete(id, req.user.id);
  }

  @Post(':id/apply')
  @Roles(UserRole.CREATOR)
  @ApiOperation({ summary: 'Apply to a campaign' })
  async apply(
    @Param('id') id: string,
    @Body('message') message: string,
    @Req() req: any,
  ) {
    this.logger.log(`Creator userId=${req.user.id} applying to campaign ${id}`);
    return this.campaignsService.apply(id, req.user, message);
  }

  @Post(':id/invite')
  @Roles(UserRole.BRAND)
  @ApiOperation({ summary: 'Invite a creator to a campaign' })
  async invite(
    @Param('id') id: string,
    @Body('creatorId') creatorId: string,
    @Req() req: any,
  ) {
    return this.campaignsService.invite(id, creatorId, req.user.id);
  }
}
