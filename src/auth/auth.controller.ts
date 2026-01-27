import { Controller, Post, Body, Get, Req, UseGuards, Res, UnauthorizedException } from '@nestjs/common'
import type { Response } from 'express'
import { AuthService } from './auth.service'
import { JwtAuthGuard } from './jwt-auth.guard'
import { SignupDto } from './dto/signup.dto'
import { LoginDto } from './dto/login.dto'
import { ApiTags, ApiBearerAuth, ApiOperation, ApiBody, ApiResponse } from '@nestjs/swagger'

@ApiTags('Auth') // Groups all routes under "Auth" in Swagger
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) { }

  @Post('login')
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
    const user = await this.authService.validateUser(loginDto.email, loginDto.password)
    const { user: userData, accessToken, refreshToken, remember } = await this.authService.login(user, loginDto.remember)

    this.setAuthCookies(res, accessToken, refreshToken, remember)
    return { user: userData }
  }

  @Post('signup')
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
  me(@Req() req: any) {
    return req.user
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
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
    })
    res.clearCookie('refresh_token', {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
    })

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
