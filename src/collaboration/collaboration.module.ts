import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CollaborationService } from './collaboration.service';
import { CollaborationController } from './collaboration.controller';
import { Conversation } from './entities/conversation.entity';
import { Message } from './entities/message.entity';
import { Application } from '../campaigns/entities/application.entity';

@Module({
    imports: [
        TypeOrmModule.forFeature([Conversation, Message, Application]),
    ],
    providers: [CollaborationService],
    controllers: [CollaborationController],
    exports: [CollaborationService],
})
export class CollaborationModule { }
