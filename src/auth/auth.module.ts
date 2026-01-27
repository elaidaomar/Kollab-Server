import { Module } from '@nestjs/common'
import { JwtModule } from '@nestjs/jwt'
import { PassportModule } from '@nestjs/passport'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { TypeOrmModule } from '@nestjs/typeorm'
import { AuthController } from './auth.controller'
import { AuthService } from './auth.service'
import { JwtStrategy } from './jwt-strategy'
import { User } from './entities/user.entity'
import { PasswordResetToken } from './entities/password-reset-token.entity'
import { RolesGuard } from './roles.guard'
import { MailService } from './mail.service'

@Module({
  imports: [
    PassportModule,
    TypeOrmModule.forFeature([User, PasswordResetToken]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET'),
        // Global JWT options; per-token expirations are configured in AuthService.
        signOptions: {
          issuer: config.get<string>('JWT_ISSUER') ?? 'kollab-api',
          audience: config.get<string>('JWT_AUDIENCE') ?? 'kollab-client',
        },
      }),
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, RolesGuard, MailService],
})
export class AuthModule { }
