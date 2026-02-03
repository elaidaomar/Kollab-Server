import { IsEmail, IsEnum } from 'class-validator'
import { ApiProperty } from '@nestjs/swagger'
import { UserRole } from '../enums/role.enum'

export class ResendVerificationDto {
    @ApiProperty({ example: 'test@example.com', required: true })
    @IsEmail()
    email: string

    @ApiProperty({ enum: UserRole })
    @IsEnum(UserRole)
    role: UserRole
}
