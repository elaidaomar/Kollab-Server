import { ApiProperty } from '@nestjs/swagger';
import { Equals, IsEmail, IsNotEmpty, MinLength } from 'class-validator';

export class DeleteAccountDto {
  @ApiProperty({ description: 'Current account password', minLength: 8 })
  @IsNotEmpty()
  @MinLength(8)
  currentPassword: string;

  @ApiProperty({
    description: 'Current account email for explicit confirmation',
  })
  @IsEmail()
  email: string;

  @ApiProperty({ description: 'Must be exactly DELETE' })
  @Equals('DELETE', { message: 'Confirmation text must be DELETE' })
  confirmText: string;
}
