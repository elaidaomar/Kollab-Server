import { Controller, Get, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { JwtAuthGuard } from './auth/jwt-auth.guard';
import { RolesGuard } from './auth/roles.guard';
import { Roles } from './auth/roles.decorator';
import { UserRole } from './auth/enums/role.enum';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  /**
   * Example creator-only endpoint protected by JWT and role guard.
   * Useful for verifying that backend role checks align with client routing.
   */
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.CREATOR)
  @Get('creator-only')
  getCreatorOnly(): string {
    return 'creator-resource';
  }

  /**
   * Example brand-only endpoint protected by JWT and role guard.
   */
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.BRAND)
  @Get('brand-only')
  getBrandOnly(): string {
    return 'brand-resource';
  }
}
