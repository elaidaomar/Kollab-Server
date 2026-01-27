import { IsEmail } from 'class-validator'
import { ApiProperty } from '@nestjs/swagger'

export class ForgotPasswordDto {
  @ApiProperty({ example: 'user@example.com', required: true })
  @IsEmail()
  email: string
}

