import { ApiProperty } from '@nestjs/swagger'
import { IsNotEmpty, MinLength } from 'class-validator'

export class ResetPasswordDto {
  @ApiProperty({ description: 'Password reset token from email link' })
  @IsNotEmpty()
  token: string

  @ApiProperty({ description: 'New password', minLength: 8 })
  @MinLength(8)
  newPassword: string
}

