import { Injectable, UnauthorizedException, ConflictException } from '@nestjs/common'
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

@Injectable()
export class AuthService {
  private readonly bcryptSaltRounds: number

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(PasswordResetToken)
    private passwordResetTokenRepository: Repository<PasswordResetToken>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private mailService: MailService,
  ) {
    const rounds = this.configService.get<number>('BCRYPT_SALT_ROUNDS')
    this.bcryptSaltRounds = typeof rounds === 'number' && !Number.isNaN(rounds) ? rounds : 10
  }

  async login(user: any, remember: boolean) {
    const { accessToken, refreshToken } = this.rotateTokens(user, remember)

    return {
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        handle: user.handle,
      },
      accessToken,
      refreshToken,
      remember, // Pass this to controller so it can set appropriate cookie maxAge
    }
  }

  async validateUser(email: string, password: string) {
    const user = await this.userRepository.findOne({
      where: { email },
      select: ['id', 'email', 'password', 'firstName', 'lastName', 'role'],
    })

    if (!user || !user.password) throw new UnauthorizedException('Invalid credentials')

    const match = await bcrypt.compare(password, user.password)
    if (!match) throw new UnauthorizedException('Invalid credentials')

    return user
  }

  async signup(data: SignupDto) {
    const existing = await this.findUserByEmail(data.email)
    if (existing) throw new ConflictException('Email already exists')

    const hashed = await bcrypt.hash(data.password, this.bcryptSaltRounds)
    const user = await this.createUser({
      ...data,
      password: hashed,
      role: UserRole.CREATOR // Force CREATOR role for all new signups
    })

    await this.generateAndSendEmailVerification(user)

    return this.login(user, false)
  }

  async findUserByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } })
  }

  async getUserById(id: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { id: id as any } }) // Cast as any if id is not string in entity
  }

  async validateToken(token: string) {
    try {
      return this.jwtService.verify(token, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      })
    } catch (e) {
      throw new UnauthorizedException('Invalid token')
    }
  }

  async createUser(data: any): Promise<User> {
    const user = this.userRepository.create(data as User)
    return this.userRepository.save(user)
  }

  private async generateAndSendEmailVerification(user: User) {
    const rawToken = crypto.randomBytes(32).toString('hex')
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex')

    const expiresMinutes = 60
    const emailVerificationExpiresAt = new Date(Date.now() + expiresMinutes * 60 * 1000)

    await this.userRepository.update(user.id, {
      emailVerificationTokenHash: tokenHash,
      emailVerificationExpiresAt,
      isEmailVerified: false,
    } as any)

    const frontendBaseUrl = this.configService.get<string>('FRONTEND_BASE_URL') ?? 'http://localhost:3000'
    const verifyUrl = `${frontendBaseUrl}/auth/verify?token=${rawToken}`

    await this.mailService.sendEmailVerificationEmail(user, verifyUrl)
  }

  async requestPasswordReset(email: string) {
    const user = await this.findUserByEmail(email)
    if (!user) {
      // Avoid user enumeration: succeed silently even if user doesn't exist
      return
    }

    // Invalidate previous tokens for this user
    await this.passwordResetTokenRepository.delete({ user: { id: user.id } as any })

    const rawToken = crypto.randomBytes(32).toString('hex')
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex')

    const expiresMinutes = 30
    const expiresAt = new Date(Date.now() + expiresMinutes * 60 * 1000)

    const resetToken = this.passwordResetTokenRepository.create({
      user,
      tokenHash,
      expiresAt,
      usedAt: null,
    })

    await this.passwordResetTokenRepository.save(resetToken)

    const frontendBaseUrl = this.configService.get<string>('FRONTEND_BASE_URL') ?? 'http://localhost:3000'
    const resetUrl = `${frontendBaseUrl}/auth/reset-password?token=${rawToken}`

    await this.mailService.sendPasswordResetEmail(user, resetUrl)
  }

  async resetPassword(token: string, newPassword: string) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex')

    const record = await this.passwordResetTokenRepository.findOne({
      where: { tokenHash },
      relations: ['user'],
    })

    if (!record || record.usedAt || record.expiresAt < new Date()) {
      throw new UnauthorizedException('Invalid or expired reset token')
    }

    const user = record.user
    const hashedPassword = await bcrypt.hash(newPassword, this.bcryptSaltRounds)
    await this.userRepository.update(user.id, { password: hashedPassword } as any)

    record.usedAt = new Date()
    await this.passwordResetTokenRepository.save(record)
  }

  async verifyEmail(token: string) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex')

    const user = await this.userRepository.findOne({
      where: { emailVerificationTokenHash: tokenHash },
    })

    if (!user || !user.emailVerificationExpiresAt || user.emailVerificationExpiresAt < new Date()) {
      throw new UnauthorizedException('Invalid or expired verification token')
    }

    await this.userRepository.update(user.id, {
      isEmailVerified: true,
      emailVerificationTokenHash: null,
      emailVerificationExpiresAt: null,
    } as any)
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
    }

    const accessToken = this.jwtService.sign(payload, {
      expiresIn: '15m',
      secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
    })

    const refreshToken = this.jwtService.sign(payload, {
      expiresIn: remember ? '30d' : '1d',
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
    })

    return { accessToken, refreshToken }
  }
}
