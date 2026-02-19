import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../auth/entities/user.entity';
import { SeedService } from './seed.service';
import { ConfigModule } from '@nestjs/config';

@Module({
    imports: [
        TypeOrmModule.forFeature([User]),
        ConfigModule,
    ],
    providers: [SeedService],
    exports: [SeedService],
})
export class SeedModule { }
