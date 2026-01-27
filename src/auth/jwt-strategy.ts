import { Injectable, UnauthorizedException } from '@nestjs/common'
import { PassportStrategy } from '@nestjs/passport'
import { ExtractJwt, Strategy } from 'passport-jwt'
import { ConfigService } from '@nestjs/config'
import { AuthService } from './auth.service'

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    config: ConfigService,
    private authService: AuthService
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: any) => {
          return request?.cookies?.access_token || null
        },
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      secretOrKey: config.get<string>('JWT_ACCESS_SECRET'),
      issuer: config.get<string>('JWT_ISSUER') ?? 'kollab-api',
      audience: config.get<string>('JWT_AUDIENCE') ?? 'kollab-client',
    })
  }

  async validate(payload: any) {
    // Verify user still exists in the database
    const user = await this.authService.getUserById(payload.sub)
    if (!user) {
      throw new UnauthorizedException('User no longer exists')
    }
    return payload // becomes req.user
  }
}
