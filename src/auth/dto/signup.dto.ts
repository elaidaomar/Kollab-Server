import { IsEmail, IsNotEmpty, MinLength, IsOptional, IsEnum, IsString } from 'class-validator'
import { ApiProperty } from '@nestjs/swagger'
import { UserRole } from '../enums/role.enum'

export class SignupDto {
    @ApiProperty({ example: 'test@example.com', required: true })
    @IsEmail()
    email: string

    @ApiProperty({ example: 'secret123', required: true })
    @MinLength(8, { message: 'Password must be at least 8 characters long' })
    password: string

    @ApiProperty({ example: 'John', required: true })
    @IsNotEmpty()
    @IsString()
    name: string

    @ApiProperty({ example: 'Doe', required: true })
    @IsNotEmpty()
    @IsString()
    surname: string

    @ApiProperty({ enum: UserRole })
    @IsEnum(UserRole)
    role: UserRole

    // Role-specific (validated in service)
    @IsOptional()
    @IsString()
    handle?: string

    @IsOptional()
    @IsString()
    company?: string
}

