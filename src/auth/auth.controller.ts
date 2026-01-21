import { Controller, Post, Body, Get, Req, UseGuards } from '@nestjs/common'
import { AuthService } from './auth.service'
import { JwtAuthGuard } from './jwt-auth.guard'

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  async login(@Body() body: any) {
    const user = await this.authService.validateUser(
      body.email,
      body.password,
    )
    return this.authService.login(user)
  }

  @Post('signup')
  async signup(@Body() body: any) {
    return this.authService.signup(body)
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  me(@Req() req: any) {
    return req.user
  }
}
