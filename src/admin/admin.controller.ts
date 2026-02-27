import {
  Controller,
  Get,
  Patch,
  Param,
  UseGuards,
  Delete,
  NotFoundException,
  InternalServerErrorException,
  Logger,
  ParseUUIDPipe,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiResponse,
} from '@nestjs/swagger';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '../auth/enums/role.enum';
import { User } from '../auth/entities/user.entity';
import { MailService } from '../auth/mail.service';
import { AuthService } from '../auth/auth.service';

@ApiTags('Admin')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.ADMIN)
@Controller('admin')
export class AdminController {
  private readonly logger = new Logger(AdminController.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private mailService: MailService,
    private authService: AuthService,
  ) {}

  @Get('users')
  @ApiOperation({ summary: 'Get all registered users (creators and brands)' })
  @ApiResponse({ status: 200, description: 'List of users' })
  async getUsers() {
    this.logger.log('Fetching users for admin...');
    const users = await this.userRepository.find({
      where: [{ role: UserRole.CREATOR }, { role: UserRole.BRAND }],
      relations: ['creatorProfile', 'brandProfile'],
      order: { createdAt: 'DESC' },
    });
    this.logger.log(`Users found: ${users.length}`);
    return users.map((user) => this.authService.serializeUser(user));
  }

  @Patch('users/:id/approve')
  @ApiOperation({ summary: 'Approve a user registration' })
  async approveUser(@Param('id', ParseUUIDPipe) id: string) {
    const user = await this.userRepository.findOneBy({ id });
    if (!user) throw new NotFoundException('User not found');

    user.isAdminApproved = true;
    user.isAdminRejected = false;
    await this.userRepository.save(user);

    try {
      await this.mailService.sendApprovalNotification(user);
    } catch (e) {
      this.logger.error(`Failed to send approval email for user ${id}`, e);
    }

    return { success: true, message: 'User approved successfully' };
  }

  @Patch('users/:id/decline')
  @ApiOperation({ summary: 'Decline a user registration or revoke approval' })
  async declineUser(@Param('id', ParseUUIDPipe) id: string) {
    const user = await this.userRepository.findOneBy({ id });
    if (!user) throw new NotFoundException('User not found');

    user.isAdminApproved = false;
    user.isAdminRejected = true;
    await this.userRepository.save(user);

    try {
      await this.mailService.sendDeclineNotification(user);
    } catch (e) {
      this.logger.error(`Failed to send decline email for user ${id}`, e);
    }

    return {
      success: true,
      message: 'User registration declined or approval revoked',
    };
  }

  @Delete('users/:id')
  @ApiOperation({ summary: 'Permanently delete a user account' })
  async deleteUser(@Param('id', ParseUUIDPipe) id: string) {
    const user = await this.userRepository.findOneBy({ id });
    if (!user) throw new NotFoundException('User not found');

    // Send notification before deleting the record, but do not block deletion if mail fails.
    try {
      await this.mailService.sendAccountDeletionNotification(user);
    } catch (e) {
      this.logger.error(`Failed to send deletion email for user ${id}`, e);
    }

    try {
      await this.userRepository.delete(id);
    } catch (e) {
      this.logger.error(`Failed to delete user ${id}`, e);
      throw new InternalServerErrorException(
        'Failed to permanently delete user account',
      );
    }

    return {
      success: true,
      message: 'User account permanently removed and notification sent',
    };
  }
}
