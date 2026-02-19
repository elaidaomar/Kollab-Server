import { ApiProperty } from '@nestjs/swagger'
import { IsNotEmpty, MinLength } from 'class-validator'

export class ChangePasswordDto {
  @ApiProperty({ description: 'Current account password', minLength: 8 })
  @IsNotEmpty()
  @MinLength(8)
  currentPassword: string

  @ApiProperty({ description: 'New account password', minLength: 8 })
  @IsNotEmpty()
  @MinLength(8)
  newPassword: string
}
