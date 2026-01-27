import { Injectable, Logger } from '@nestjs/common'
import { User } from './entities/user.entity'

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name)

  async sendPasswordResetEmail(user: User, resetUrl: string) {
    // Stub implementation – integrate with real provider (SendGrid, SES, etc.) later.
    this.logger.log(`Password reset email to ${user.email}: ${resetUrl}`)
  }

  async sendEmailVerificationEmail(user: User, verifyUrl: string) {
    this.logger.log(`Email verification to ${user.email}: ${verifyUrl}`)
  }
}

