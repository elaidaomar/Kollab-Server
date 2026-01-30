import { Injectable, Logger } from '@nestjs/common'
import { User } from './entities/user.entity'
import { MailerService } from '@nestjs-modules/mailer'

@Injectable()
export class MailService {
  constructor(private readonly mailerService: MailerService) { }
  private readonly logger = new Logger(MailService.name)

  async sendPasswordResetEmail(user: User, resetUrl: string) {
    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Password Reset',
      template: 'password-reset',
      context: {
        resetUrl,
      },
    })
    this.logger.log(`Password reset email to ${user.email}: ${resetUrl}`)
  }

  async sendEmailVerificationEmail(user: User, verifyUrl: string) {
    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Email Verification',
      template: 'email-verification',
      context: {
        verifyUrl,
      },
    })
    this.logger.log(`Email verification to ${user.email}: ${verifyUrl}`)
  }

  async sendTestEmail() {
    await this.mailerService.sendMail({
      to: 'user@local.test', // any dummy email
      subject: 'Test Email from NestJS',
      text: 'Hello from NestJS via Mailpit!',
      html: '<b>Hello from NestJS via Mailpit!</b>',
    });
  }
}

