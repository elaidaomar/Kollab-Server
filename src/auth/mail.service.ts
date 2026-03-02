import { Injectable, Logger } from '@nestjs/common';
import { User } from './entities/user.entity';
import { MailerService } from '@nestjs-modules/mailer';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailService {
  constructor(
    private readonly mailerService: MailerService,
    private readonly configService: ConfigService,
  ) { }
  private readonly logger = new Logger(MailService.name);

  async sendPasswordResetEmail(user: User, resetUrl: string) {
    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Password Reset',
      template: 'password-reset',
      context: {
        resetUrl,
      },
    });
    this.logger.log(`Password reset email to ${user.email}: ${resetUrl}`);
  }

  async sendEmailVerificationEmail(user: User, verifyUrl: string) {
    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Email Verification',
      template: 'email-verification',
      context: {
        verifyUrl,
      },
    });
    this.logger.log(`Email verification to ${user.email}: ${verifyUrl}`);
  }

  async sendApprovalNotification(user: User) {
    const frontendBaseUrl = (
      this.configService.get<string>('FRONTEND_BASE_URL') ??
      'http://localhost:3000'
    ).replace(/\/+$/, '');
    const loginUrl = `${frontendBaseUrl}/auth/${user.role}/login`;

    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Account Approved - Welcome to Kollab!',
      template: 'account-approved',
      context: {
        name: user.name,
        surname: user.surname,
        loginUrl,
      },
    });
    this.logger.log(`Approval notification sent to ${user.email}`);
  }

  async sendDeclineNotification(user: User) {
    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Update regarding your Kollab registration',
      template: 'account-declined',
      context: {
        name: user.name,
      },
    });
    this.logger.log(`Decline notification sent to ${user.email}`);
  }

  async sendAccountDeletionNotification(user: User) {
    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Kollab Account Permanently Deleted',
      template: 'account-deleted',
      context: {
        name: user.name,
      },
    });
    this.logger.log(`Account deletion notification sent to ${user.email}`);
  }

  async sendApplicationAcceptedEmail(user: User, campaignTitle: string) {
    await this.mailerService.sendMail({
      to: user.email,
      subject: `Application Accepted: ${campaignTitle}`,
      template: 'application-accepted',
      context: {
        name: user.name,
        campaignTitle,
      },
    });
    this.logger.log(`Application accepted email sent to ${user.email} for campaign ${campaignTitle}`);
  }

  async sendApplicationRejectedEmail(user: User, campaignTitle: string) {
    await this.mailerService.sendMail({
      to: user.email,
      subject: `Update on your application: ${campaignTitle}`,
      template: 'application-rejected',
      context: {
        name: user.name,
        campaignTitle,
      },
    });
    this.logger.log(`Application rejected email sent to ${user.email} for campaign ${campaignTitle}`);
  }

  async sendCampaignInvitationEmail(user: User, campaignTitle: string, brandName: string, campaignId: string) {
    const frontendBaseUrl = (
      this.configService.get<string>('FRONTEND_BASE_URL') ??
      'http://localhost:3000'
    ).replace(/\/+$/, '');
    const campaignUrl = `${frontendBaseUrl}/creator/campaigns/${campaignId}`;

    await this.mailerService.sendMail({
      to: user.email,
      subject: `Invitation: ${brandName} wants you for "${campaignTitle}"`,
      template: 'campaign-invitation',
      context: {
        name: user.name,
        brandName,
        campaignTitle,
        campaignUrl,
      },
    });
    this.logger.log(`Campaign invitation email sent to ${user.email} for campaign ${campaignTitle} by ${brandName}`);
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
