import {
  CanActivate,
  ExecutionContext,
  Injectable,
  ForbiddenException,
} from '@nestjs/common';
import { UserRole } from '../enums/role.enum';
import { User } from '../entities/user.entity';

@Injectable()
export class ApprovedGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const user = request.user as User;

    if (!user) {
      return false;
    }

    // Admins always pass
    if (user.role === UserRole.ADMIN) {
      return true;
    }

    // Creators and Brands must be both email verified and admin approved
    if (!user.isEmailVerified) {
      throw new ForbiddenException('Please verify your email address first.');
    }

    if (!user.isAdminApproved) {
      throw new ForbiddenException(
        'Your account is pending approval by the Kollab team. We will notify you once it is ready!',
      );
    }

    return true;
  }
}
