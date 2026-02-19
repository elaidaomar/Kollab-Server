import { Controller, Get, Patch, Param, UseGuards, Query } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiResponse } from '@nestjs/swagger';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '../auth/enums/role.enum';
import { User } from '../auth/entities/user.entity';
import { MailService } from '../auth/mail.service';

@ApiTags('Admin')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.ADMIN)
@Controller('admin')
export class AdminController {
    constructor(
        @InjectRepository(User)
        private userRepository: Repository<User>,
        private mailService: MailService,
    ) { }

    @Get('users')
    @ApiOperation({ summary: 'Get all registered users (creators and brands)' })
    @ApiResponse({ status: 200, description: 'List of users' })
    async getUsers() {
        return this.userRepository.find({
            where: [
                { role: UserRole.CREATOR },
                { role: UserRole.BRAND },
            ],
            relations: ['creatorProfile', 'brandProfile'],
            order: { createdAt: 'DESC' },
        });
    }

    @Patch('users/:id/approve')
    @ApiOperation({ summary: 'Approve a user registration' })
    async approveUser(@Param('id') id: string) {
        const user = await this.userRepository.findOneBy({ id: id as any });
        if (!user) throw new Error('User not found');

        user.isAdminApproved = true;
        await this.userRepository.save(user);

        await this.mailService.sendApprovalNotification(user);

        return { success: true, message: 'User approved successfully' };
    }

    @Patch('users/:id/decline')
    @ApiOperation({ summary: 'Decline a user registration' })
    async declineUser(@Param('id') id: string) {
        const user = await this.userRepository.findOneBy({ id: id as any });
        if (!user) throw new Error('User not found');

        user.isAdminApproved = false;
        await this.userRepository.save(user);

        await this.mailService.sendDeclineNotification(user);

        return { success: true, message: 'User declined successfully' };
    }
}
