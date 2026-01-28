import { IsBoolean, IsEmail, IsEnum, isEnum, IsNotEmpty } from 'class-validator'
import { ApiProperty } from '@nestjs/swagger'
import { UserRole } from '../enums/role.enum';

export class LoginDto {
    @ApiProperty({ example: 'test@example.com', required: true })
    @IsEmail()
    email: string

    @ApiProperty({ example: 'secret123', required: true })
    @IsNotEmpty()
    password: string

    @ApiProperty({ example: 'creator', required: false })
    @IsNotEmpty()
    role: string;

    @IsBoolean()
    @ApiProperty({ example: false, required: false })
    remember: boolean;
}
