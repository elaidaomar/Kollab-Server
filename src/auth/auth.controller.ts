import {
  Controller,
  Post,
  Body,
  Get,
  Req,
  UseGuards,
  Res,
  UnauthorizedException,
  Query,
  UsePipes,
  Logger,
  Put,
  Delete,
} from '@nestjs/common';
import type { Response } from 'express';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ResendVerificationDto } from './dto/resend-verification.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { DeleteAccountDto } from './dto/delete-account.dto';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiBody,
  ApiResponse,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { AuthValidationPipe } from './pipes/auth-validation.pipe';
import { ApprovedGuard } from './guards/approved.guard';
import { EmailVerifiedGuard } from './guards/email-verified.guard';

@ApiTags('Auth') // Groups all routes under "Auth" in Swagger
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger();
  constructor(private authService: AuthService) {}

  @Post('login')
  @UsePipes(new AuthValidationPipe('Invalid credentials'))
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @ApiOperation({ summary: 'Login user with email and password' })
  @ApiBody({
    description: 'User credentials',
    examples: {
      example: {
        value: {
          email: 'test@example.com',
          password: 'secret',
          remember: false,
        },
      },
    },
  })
  @ApiResponse({ status: 201, description: 'User logged in successfully' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.authService.validateUser(
      loginDto.email,
      loginDto.password,
      loginDto.role,
    );
    const {
      user: userData,
      accessToken,
      refreshToken,
      remember,
    } = await this.authService.login(user, loginDto.remember);
    this.logger.log(userData);

    this.setAuthCookies(res, accessToken, refreshToken, remember);
    return { user: userData };
  }

  @Post('signup')
  @UsePipes(new AuthValidationPipe('Invalid registration data'))
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @ApiOperation({ summary: 'Register a new user' })
  @ApiBody({
    description: 'User registration data',
    examples: {
      example: {
        value: {
          email: 'test@example.com',
          password: 'secret',
          name: 'John',
          handle: '@john',
        },
      },
    },
  })
  @ApiResponse({ status: 201, description: 'User created successfully' })
  async signup(
    @Body() signupDto: SignupDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const {
      user: userData,
      accessToken,
      refreshToken,
    } = await this.authService.signup(signupDto);
    this.setAuthCookies(res, accessToken, refreshToken);
    return { user: userData };
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  @ApiOperation({ summary: 'Get current logged-in user' })
  @ApiBearerAuth() // Shows "Authorize" button in Swagger
  @ApiResponse({ status: 200, description: 'Returns current user info' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async me(@Req() req: any) {
    const user = req.user;
    return this.authService.serializeUser(user);
  }

  @UseGuards(JwtAuthGuard, ApprovedGuard, EmailVerifiedGuard)
  @Get('profile')
  @ApiOperation({ summary: 'Get current user profile for settings' })
  @ApiBearerAuth()
  async getProfile(@Req() req: any) {
    return this.authService.getProfile(req.user.id);
  }

  @UseGuards(JwtAuthGuard, ApprovedGuard, EmailVerifiedGuard)
  @Put('profile')
  @ApiOperation({ summary: 'Update current user general profile settings' })
  @ApiBearerAuth()
  @ApiBody({ type: UpdateProfileDto })
  async updateProfile(@Req() req: any, @Body() body: UpdateProfileDto) {
    return this.authService.updateProfile(req.user.id, body);
  }

  @UseGuards(JwtAuthGuard, ApprovedGuard, EmailVerifiedGuard)
  @Put('password')
  @ApiOperation({ summary: 'Change current user password from settings' })
  @ApiBearerAuth()
  @ApiBody({ type: ChangePasswordDto })
  async changePassword(@Req() req: any, @Body() body: ChangePasswordDto) {
    return this.authService.changePassword(req.user.id, body);
  }

  @UseGuards(JwtAuthGuard, ApprovedGuard, EmailVerifiedGuard)
  @Delete('account')
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @ApiOperation({
    summary:
      'Permanently delete the authenticated account after strict confirmation',
  })
  @ApiBearerAuth()
  @ApiBody({ type: DeleteAccountDto })
  async deleteAccount(
    @Req() req: any,
    @Body() body: DeleteAccountDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.deleteOwnAccount(req.user.id, body);
    res.clearCookie('access_token', {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
    });
    res.clearCookie('refresh_token', {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
    });
    return { success: true };
  }

  @Post('refresh')
  @ApiOperation({ summary: 'Refreshes user token' })
  async refresh(@Req() req: any, @Res({ passthrough: true }) res: Response) {
    const token = req.cookies.refresh_token;
    if (!token) throw new UnauthorizedException('Refresh token missing');

    const payload = await this.authService.validateToken(token);
    const user = await this.authService.getUserById(payload.sub);
    if (!user) throw new UnauthorizedException('User not found');

    // Maintain "remember" status from the old token
    const remember = !!payload.remember;

    const {
      user: userData,
      accessToken,
      refreshToken,
    } = await this.authService.login(user, remember);
    this.setAuthCookies(res, accessToken, refreshToken, remember);
    return { user: userData };
  }

  @Post('logout')
  @ApiOperation({ summary: 'Log out user' })
  logout(@Res({ passthrough: true }) res: Response) {
    res.clearCookie('access_token', {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
    });
    res.clearCookie('refresh_token', {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
    });

    return { success: true };
  }

  @Post('forgot-password')
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @ApiOperation({ summary: 'Request a password reset email' })
  @ApiBody({ type: ForgotPasswordDto })
  @ApiResponse({
    status: 201,
    description: 'Password reset email requested (generic response)',
  })
  async forgotPassword(@Body() body: ForgotPasswordDto) {
    // Always respond success to avoid leaking user existence
    await this.authService.requestPasswordReset(body.email, body.role);
    return { success: true };
  }

  @Post('reset-password')
  @UsePipes(new AuthValidationPipe())
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @ApiOperation({ summary: 'Reset password using a reset token' })
  @ApiBody({ type: ResetPasswordDto })
  @ApiResponse({ status: 201, description: 'Password successfully reset' })
  async resetPassword(@Body() body: ResetPasswordDto) {
    await this.authService.resetPassword(body.token, body.newPassword);
    return { success: true };
  }

  @Post('resend-verification')
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @ApiOperation({ summary: 'Resend email verification link' })
  @ApiBody({ type: ResendVerificationDto })
  @ApiResponse({
    status: 201,
    description: 'Verification email resent if user exists and not verified',
  })
  async resendVerification(@Body() body: ResendVerificationDto) {
    await this.authService.resendEmailVerification(body.email, body.role);
    return { success: true };
  }

  @Get('verify')
  @ApiOperation({ summary: 'Verify email using a verification token' })
  @ApiResponse({ status: 200, description: 'Email successfully verified' })
  async verifyEmail(
    @Query('token') token: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.authService.verifyEmail(token);
    const {
      user: userData,
      accessToken,
      refreshToken,
    } = await this.authService.login(user, false);
    this.setAuthCookies(res, accessToken, refreshToken, false);
    return { success: true, user: userData };
  }

  @Get('reset-password/validate')
  @ApiOperation({ summary: 'Validate a password reset token' })
  @ApiResponse({ status: 200, description: 'Token is valid' })
  @ApiResponse({ status: 401, description: 'Token is invalid or expired' })
  async validateResetToken(@Query('token') token: string) {
    await this.authService.validatePasswordResetToken(token);
    return { success: true };
  }

  private setAuthCookies(
    res: Response,
    accessToken: string,
    refreshToken: string,
    remember: boolean = false,
  ) {
    // Set short-lived access token cookie (15m)
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax', // Changed from 'strict' to 'lax' to support cross-port local development
      maxAge: 15 * 60 * 1000,
    });

    // Set refresh token cookie - session-based if not remembered, long-lived if remembered
    const refreshTokenOptions: any = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax', // Matches access_token
    };

    // If remember is true, set maxAge to 30 days, otherwise make it a session cookie
    if (remember) {
      refreshTokenOptions.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days (matches JWT)
    }
    // If maxAge is not set, cookie becomes a session cookie (deleted when browser closes)

    res.cookie('refresh_token', refreshToken, refreshTokenOptions);
  }
}
