import { Injectable, UnauthorizedException, ConflictException, BadRequestException, Logger } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { InjectRepository } from '@nestjs/typeorm'
import { Repository } from 'typeorm'
import { ConfigService } from '@nestjs/config'
import * as bcrypt from 'bcrypt'
import { User } from './entities/user.entity'
import { PasswordResetToken } from './entities/password-reset-token.entity'
import { SignupDto } from './dto/signup.dto'
import { UserRole } from './enums/role.enum'
import { MailService } from './mail.service'
import * as crypto from 'crypto'
import { CreatorProfile } from './entities/creator-profile.entity'
import { BrandProfile } from './entities/brand-profile.entity'

@Injectable()
export class AuthService {
  private readonly bcryptSaltRounds: number;
  private readonly logger = new Logger();

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(PasswordResetToken)
    private passwordResetTokenRepository: Repository<PasswordResetToken>,
    @InjectRepository(CreatorProfile)
    private creatorProfileRepository: Repository<CreatorProfile>,
    @InjectRepository(BrandProfile)
    private brandProfileRepository: Repository<BrandProfile>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private mailService: MailService,
  ) {
    const rounds = this.configService.get<number>('BCRYPT_SALT_ROUNDS');
    this.bcryptSaltRounds =
      typeof rounds === 'number' && !Number.isNaN(rounds) ? rounds : 12; // Standardized to 12 for better security
  }

  async login(user: User, remember: boolean) {
    let handle: string | undefined
    let company: string | undefined

    if (user.role === UserRole.CREATOR) {
      const profile = await this.creatorProfileRepository.findOne({ where: { user: { id: user.id } } })
      handle = profile?.handle
    }

    if (user.role === UserRole.BRAND) {
      const profile = await this.brandProfileRepository.findOne({ where: { user: { id: user.id } } })
      company = profile?.company
    }

    const { accessToken, refreshToken } = this.rotateTokens(user, remember)

    return {
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        surname: user.surname,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        handle,
        company,
      },
      accessToken,
      refreshToken,
      remember,
    }
  }

  async validateUser(email: string, password: string, role: string) {
    if (!role || !Object.values(UserRole).includes(role as UserRole)) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const user = await this.userRepository.findOne({
      where: { email, role: role as UserRole },
      select: ['id', 'email', 'password', 'name', 'surname', 'role', 'isEmailVerified'],
    });

    if (!user || !user.password)
      throw new UnauthorizedException('Invalid credentials');

    const match = await bcrypt.compare(password, user.password);
    if (!match) throw new UnauthorizedException('Invalid credentials');

    return user;
  }

  async signup(data: SignupDto) {
    const existing = await this.findUserByEmailAndRole(data.email, data.role)
    this.logger.debug(existing);
    if (existing) throw new ConflictException('Email already exists')

    // Role-specific validation
    if (data.role === UserRole.CREATOR && !data.handle) {
      throw new BadRequestException('Handle is required for creators')
    }

    if (data.role === UserRole.BRAND && !data.company) {
      throw new BadRequestException('Company name is required for brands')
    }

    const hashed = await bcrypt.hash(data.password, this.bcryptSaltRounds)

    // Create base user
    const user = await this.userRepository.save({
      email: data.email,
      password: hashed,
      role: data.role,
      name: data.name,
      surname: data.surname,
    })

    // Create role profile
    if (data.role === UserRole.CREATOR) {
      await this.createCreatorProfile({
        user,
        handle: data.handle!,
      })
    }

    if (data.role === UserRole.BRAND) {
      await this.createBrandProfile({
        user,
        company: data.company!,
      })
    }

    await this.generateAndSendEmailVerification(user)
    return this.login(user, false)
  }

  async findUserByEmailAndRole(email: string, role: UserRole): Promise<User | null> {
    return this.userRepository.findOne({ where: { email, role } });
  }

  async getUserById(id: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { id: id as any }, relations: ['creatorProfile', 'brandProfile'] }); // Cast as any if id is not string in entity
  }

  async validateToken(token: string) {
    try {
      return this.jwtService.verify(token, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      });
    } catch (e) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  async createUser(data: any): Promise<User> {
    const user = this.userRepository.create(data as User);
    return this.userRepository.save(user);
  }

  async createCreatorProfile(data: any): Promise<CreatorProfile> {
    const creator = this.creatorProfileRepository.create(data as CreatorProfile);
    return this.creatorProfileRepository.save(creator);
  }

  async createBrandProfile(data: any): Promise<BrandProfile> {
    const brand = this.brandProfileRepository.create(data as BrandProfile);
    return this.brandProfileRepository.save(brand);
  }

  private async generateAndSendEmailVerification(user: User) {
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto
      .createHash('sha256')
      .update(rawToken)
      .digest('hex');

    const expiresMinutes = 60;
    const emailVerificationExpiresAt = new Date(
      Date.now() + expiresMinutes * 60 * 1000,
    );

    await this.userRepository.update(user.id, {
      emailVerificationTokenHash: tokenHash,
      emailVerificationExpiresAt,
      isEmailVerified: false,
    } as any);

    const frontendBaseUrl =
      this.configService.get<string>('FRONTEND_BASE_URL') ??
      'http://localhost:3000';
    const verifyUrl = `${frontendBaseUrl}/auth/${user.role}/verify?token=${rawToken}`;

    await this.mailService.sendEmailVerificationEmail(user, verifyUrl);
  }

  async requestPasswordReset(email: string, role: UserRole) {
    const user = await this.findUserByEmailAndRole(email, role);
    if (!user) {
      // Avoid user enumeration: succeed silently even if user doesn't exist
      return;
    }

    // Invalidate previous tokens for this user
    await this.passwordResetTokenRepository.delete({
      user: { id: user.id } as any,
    });

    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto
      .createHash('sha256')
      .update(rawToken)
      .digest('hex');

    const expiresMinutes = 30;
    const expiresAt = new Date(Date.now() + expiresMinutes * 60 * 1000);

    const resetToken = this.passwordResetTokenRepository.create({
      user,
      tokenHash,
      expiresAt,
      usedAt: null,
    });

    await this.passwordResetTokenRepository.save(resetToken);

    const frontendBaseUrl =
      this.configService.get<string>('FRONTEND_BASE_URL') ??
      'http://localhost:3000';
    const resetUrl = `${frontendBaseUrl}/auth/${user.role}/reset-password?token=${rawToken}`;

    await this.mailService.sendPasswordResetEmail(user, resetUrl);
  }

  async resetPassword(token: string, newPassword: string) {
    // Hash the incoming token for comparison
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    // Find the token record with user relation
    const record = await this.passwordResetTokenRepository.findOne({
      where: { tokenHash },
      relations: ['user'],
    });

    // Validate token
    if (!record || record.usedAt || record.expiresAt < new Date()) {
      throw new UnauthorizedException('Invalid or expired reset token');
    }

    const user = record.user;

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, this.bcryptSaltRounds);

    // Update the user's password AND invalidate the token
    await Promise.all([
      this.userRepository.update(user.id, { password: hashedPassword } as any),
      this.passwordResetTokenRepository.update(record.id, { usedAt: new Date() } as any),
    ]);
  }

  async validatePasswordResetToken(token: string) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const record = await this.passwordResetTokenRepository.findOne({
      where: { tokenHash },
    });

    if (!record || record.usedAt || record.expiresAt < new Date()) {
      throw new UnauthorizedException('Invalid or expired reset token');
    }
    return true;
  }

  async verifyEmail(token: string): Promise<void> {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    const user = await this.userRepository.findOne({
      where: { emailVerificationTokenHash: tokenHash },
    });

    if (
      !user ||
      !user.emailVerificationExpiresAt ||
      user.emailVerificationExpiresAt < new Date()
    ) {
      throw new UnauthorizedException('Invalid or expired verification token');
    }

    // If already verified, just clear token fields (idempotent safety)
    if (user.isEmailVerified) {
      await this.userRepository.update(user.id, {
        emailVerificationTokenHash: null,
        emailVerificationExpiresAt: null,
      } as any);
      return;
    }

    await this.userRepository.update(user.id, {
      isEmailVerified: true,
      emailVerificationTokenHash: null,
      emailVerificationExpiresAt: null,
    } as any);
  }


  async resendEmailVerification(email: string, role: UserRole) {
    const user = await this.findUserByEmailAndRole(email, role)
    if (!user || user.isEmailVerified) {
      // Still return success to avoid enumeration and unnecessary noise
      return
    }
    await this.generateAndSendEmailVerification(user)
  }

  /**
   * Central helper for issuing new access/refresh token pairs.
   * Access tokens are short-lived (15m); refresh tokens are longer-lived
   * and respect the "remember me" flag.
   */
  rotateTokens(user: User, remember: boolean) {
    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role,
      remember,
    };

    const accessToken = this.jwtService.sign(payload, {
      expiresIn: '15m',
      secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
    });

    const refreshToken = this.jwtService.sign(payload, {
      expiresIn: remember ? '30d' : '1d',
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
    });

    return { user: user, accessToken, refreshToken };
  }
}
