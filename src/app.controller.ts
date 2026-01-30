import { Controller, Get, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { JwtAuthGuard } from './auth/guards/jwt-auth.guard';
import { RolesGuard } from './auth/guards/roles.guard';
import { Roles } from './auth/decorators/roles.decorator';
import { UserRole } from './auth/enums/role.enum';
import { EmailVerifiedGuard } from './auth/guards/email-verified-guard';
import { MailService } from './auth/mail.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService, private mailService: MailService) { }

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  /**
   * Example creator-only endpoint protected by JWT and role guard.
   * Useful for verifying that backend role checks align with client routing.
   */
  @UseGuards(JwtAuthGuard, RolesGuard, EmailVerifiedGuard)
  @Roles(UserRole.CREATOR)
  @Get('creator-only')
  getCreatorOnly(): string {
    return 'creator-resource';
  }

  /**
   * Example brand-only endpoint protected by JWT and role guard.
   */
  @UseGuards(JwtAuthGuard, RolesGuard, EmailVerifiedGuard)
  @Roles(UserRole.BRAND)
  @Get('brand-only')
  getBrandOnly(): string {
    return 'brand-resource';
  }

  // @Get('test-email')
  // testEmail() {
  //   return this.mailService.sendTestEmail();
  // }
}
