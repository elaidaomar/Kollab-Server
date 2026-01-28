import { IsEmail, IsEnum } from 'class-validator'
import { ApiProperty } from '@nestjs/swagger'
import { UserRole } from '../enums/role.enum';

export class ForgotPasswordDto {
  @ApiProperty({ example: 'user@example.com', required: true })
  @IsEmail()
  email: string;

  @ApiProperty({ enum: UserRole })
  @IsEnum(UserRole)
  role: UserRole;
}

