import { Controller, Post, Body, Get, Req, UseGuards, Res } from '@nestjs/common'
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
    const { token, user: userData } = await this.authService.login(user, loginDto.remember)

    res.cookie('jwt', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: loginDto.remember ? 7 * 24 * 60 * 60 * 1000 : 15 * 60 * 1000,
    })

    return { user: userData }
  }

  @Post('signup')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiBody({
    description: 'User registration data',
    examples: {
      example: {
        value: { email: 'test@example.com', password: 'secret', name: 'John' }
      }
    }
  })
  @ApiResponse({ status: 201, description: 'User created successfully' })
  async signup(
    @Body() signupDto: SignupDto,
    @Res({ passthrough: true }) res: Response
  ) {
    const { token, user } = await this.authService.signup(signupDto)

    res.cookie('jwt', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000, // Short lived for signup
    })

    return { user }
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

  @Post('logout')
  logout(@Res({ passthrough: true }) res: Response) {
    res.clearCookie('jwt', {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
    })

    return { success: true }
  }

}
