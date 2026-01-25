import { IsEmail, IsNotEmpty, MinLength, IsOptional, IsEnum, IsString } from 'class-validator'
import { ApiProperty } from '@nestjs/swagger'
import { UserRole } from '../enums/role.enum'

export class SignupDto {
    @ApiProperty({ example: 'test@example.com', required: true })
    @IsEmail()
    email: string

    @ApiProperty({ example: 'secret123', required: true })
    @MinLength(6)
    password: string

    @ApiProperty({ example: 'John Doe', required: true })
    @IsOptional()
    name?: string

    @ApiProperty({ example: '@john', required: true })
    @IsNotEmpty()
    @IsString()
    handle: string

    @ApiProperty({ enum: UserRole, default: UserRole.CREATOR, required: true })
    @IsOptional()
    @IsEnum(UserRole)
    role?: UserRole
}
