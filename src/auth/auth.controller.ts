import { Controller, Post, Body, Get, Req, UseGuards } from '@nestjs/common'
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
        value: { email: 'test@example.com', password: 'secret' }
      }
    }
  })
  @ApiResponse({ status: 201, description: 'User logged in successfully' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  async login(@Body() loginDto: LoginDto) {
    const user = await this.authService.validateUser(loginDto.email, loginDto.password)
    return this.authService.login(user)
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
  async signup(@Body() signupDto: SignupDto) {
    return this.authService.signup(signupDto)
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
}
