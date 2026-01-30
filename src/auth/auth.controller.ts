import { Controller, Post, Body, Get, Req, UseGuards, Res, UnauthorizedException, Query, UsePipes, Logger } from '@nestjs/common'
import type { Response } from 'express'
import { AuthService } from './auth.service'
import { JwtAuthGuard } from './guards/jwt-auth.guard'
import { SignupDto } from './dto/signup.dto'
import { LoginDto } from './dto/login.dto'
import { ForgotPasswordDto } from './dto/forgot-password.dto'
import { ResetPasswordDto } from './dto/reset-password.dto'
import { ApiTags, ApiBearerAuth, ApiOperation, ApiBody, ApiResponse } from '@nestjs/swagger'
import { Throttle } from '@nestjs/throttler'
import { AuthValidationPipe } from './pipes/auth-validation.pipe'
import { log } from 'console'
import { UserRole } from './enums/role.enum'
import { RolesGuard } from './guards/roles.guard'

@ApiTags('Auth') // Groups all routes under "Auth" in Swagger
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger();
  constructor(private authService: AuthService) { }

  @Post('login')
  @UsePipes(new AuthValidationPipe("Invalid credentials"))
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @ApiOperation({ summary: 'Login user with email and password' })
  @ApiBody({
    description: 'User credentials',
    examples: {
      example: {
        value: { email: 'test@example.com', password: 'secret', remember: false }
      }
    }
  })
  @ApiResponse({ status: 201, description: 'User logged in successfully' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response
  ) {
    const user = await this.authService.validateUser(loginDto.email, loginDto.password, loginDto.role)
    const { user: userData, accessToken, refreshToken, remember } = await this.authService.login(user, loginDto.remember)
    this.logger.log(userData);

    this.setAuthCookies(res, accessToken, refreshToken, remember)
    return { user: userData }
  }

  @Post('signup')
  @UsePipes(new AuthValidationPipe("Invalid registration data"))
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @ApiOperation({ summary: 'Register a new user' })
  @ApiBody({
    description: 'User registration data',
    examples: {
      example: {
        value: { email: 'test@example.com', password: 'secret', name: 'John', handle: '@john' }
      }
    }
  })
  @ApiResponse({ status: 201, description: 'User created successfully' })
  async signup(
    @Body() signupDto: SignupDto,
    @Res({ passthrough: true }) res: Response
  ) {
    const { user: userData, accessToken, refreshToken } = await this.authService.signup(signupDto)
    this.setAuthCookies(res, accessToken, refreshToken)
    return { user: userData }
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  @ApiOperation({ summary: 'Get current logged-in user' })
  @ApiBearerAuth() // Shows "Authorize" button in Swagger
  @ApiResponse({ status: 200, description: 'Returns current user info' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async me(@Req() req: any) {
    const user = await this.authService.getUserById(req.user.sub)

    if (!user) {
      // Optional: handle case where user was deleted after token was issued
      throw new UnauthorizedException('User not found')
    }

    // Return role-specific fields safely
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      surname: user.surname,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      ...(user.role === UserRole.CREATOR ? { handle: user.creatorProfile?.handle } : {}),
      ...(user.role === UserRole.BRAND ? { company: user.brandProfile?.company } : {}),
    }
  }

  @Post('refresh')
  async refresh(@Req() req: any, @Res({ passthrough: true }) res: Response) {
    const token = req.cookies.refresh_token
    if (!token) throw new UnauthorizedException('Refresh token missing')

    const payload = await this.authService.validateToken(token)
    const user = await this.authService.getUserById(payload.sub)
    if (!user) throw new UnauthorizedException('User not found')

    // Maintain "remember" status from the old token
    const remember = !!payload.remember

    const { user: userData, accessToken, refreshToken } = await this.authService.login(user, remember)
    this.setAuthCookies(res, accessToken, refreshToken, remember)
    return { user: userData }
  }

  @Post('logout')
  logout(@Res({ passthrough: true }) res: Response) {
    res.clearCookie('access_token', {
      httpOnly: true,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production',
    })
    res.clearCookie('refresh_token', {
      httpOnly: true,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production',
    })

    return { success: true }
  }

  @Post('forgot-password')
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @ApiOperation({ summary: 'Request a password reset email' })
  @ApiBody({ type: ForgotPasswordDto })
  @ApiResponse({ status: 201, description: 'Password reset email requested (generic response)' })
  async forgotPassword(@Body() body: ForgotPasswordDto) {
    // Always respond success to avoid leaking user existence
    await this.authService.requestPasswordReset(body.email, body.role)
    return { success: true }
  }

  @Post('reset-password')
  @UsePipes(new AuthValidationPipe())
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @ApiOperation({ summary: 'Reset password using a reset token' })
  @ApiBody({ type: ResetPasswordDto })
  @ApiResponse({ status: 201, description: 'Password successfully reset' })
  async resetPassword(@Body() body: ResetPasswordDto) {
    await this.authService.resetPassword(body.token, body.newPassword)
    return { success: true }
  }

  @Get('verify')
  @ApiOperation({ summary: 'Verify email using a verification token' })
  @ApiResponse({ status: 200, description: 'Email successfully verified' })
  async verifyEmail(@Query('token') token: string) {
    await this.authService.verifyEmail(token)
    return { success: true }
  }

  private setAuthCookies(res: Response, accessToken: string, refreshToken: string, remember: boolean = false) {
    // Set short-lived access token cookie (15m)
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000,
    })

    // Set refresh token cookie - session-based if not remembered, long-lived if remembered
    const refreshTokenOptions: any = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
    }

    // If remember is true, set maxAge to 30 days, otherwise make it a session cookie
    if (remember) {
      refreshTokenOptions.maxAge = 30 * 24 * 60 * 60 * 1000 // 30 days (matches JWT)
    }
    // If maxAge is not set, cookie becomes a session cookie (deleted when browser closes)

    res.cookie('refresh_token', refreshToken, refreshTokenOptions)
  }
}
