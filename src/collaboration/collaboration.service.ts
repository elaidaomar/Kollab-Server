import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Conversation } from './entities/conversation.entity';
import { Message, MessageType } from './entities/message.entity';
import { User } from '../auth/entities/user.entity';
import { Application, ApplicationStatus } from '../campaigns/entities/application.entity';

@Injectable()
export class CollaborationService {
    constructor(
        @InjectRepository(Conversation)
        private conversationRepository: Repository<Conversation>,
        @InjectRepository(Message)
        private messageRepository: Repository<Message>,
        @InjectRepository(Application)
        private applicationRepository: Repository<Application>,
    ) { }

    async getOrCreateConversation(applicationId: string, user: User) {
        const application = await this.applicationRepository.findOne({
            where: { id: applicationId },
            relations: ['campaign', 'campaign.brand', 'campaign.brand.brandProfile', 'creator', 'creator.creatorProfile'],
        });

        if (!application) {
            throw new NotFoundException('Application not found');
        }

        // Check if user is either the brand or the creator
        const isBrand = application.campaign.brand.id === user.id;
        const isCreator = application.creator.id === user.id;

        if (!isBrand && !isCreator && user.role !== 'admin') {
            throw new ForbiddenException('You do not have access to this collaboration');
        }

        let conversation = await this.conversationRepository.findOne({
            where: { application: { id: applicationId } },
            relations: [
                'messages',
                'messages.sender',
                'application',
                'application.campaign',
                'application.campaign.brand',
                'application.campaign.brand.brandProfile',
                'application.creator',
                'application.creator.creatorProfile'
            ],
        });

        if (!conversation) {
            conversation = this.conversationRepository.create({
                application,
            });
            await this.conversationRepository.save(conversation);

            // Create initial system message
            await this.createSystemMessage(
                conversation,
                `${application.campaign.brand.brandProfile?.company || application.campaign.brand.name} has accepted your application. Collaboration started!`,
                'collaboration_started'
            );
        }

        return conversation;
    }

    async getMessages(conversationId: string, user: User) {
        const conversation = await this.conversationRepository.findOne({
            where: { id: conversationId },
            relations: ['application', 'application.campaign', 'application.campaign.brand', 'application.creator'],
        });

        if (!conversation) {
            throw new NotFoundException('Conversation not found');
        }

        const isBrand = conversation.application.campaign.brand.id === user.id;
        const isCreator = conversation.application.creator.id === user.id;

        if (!isBrand && !isCreator && user.role !== 'admin') {
            throw new ForbiddenException('Access denied');
        }

        return this.messageRepository.find({
            where: { conversation: { id: conversationId } },
            relations: ['sender'],
            order: { createdAt: 'ASC' },
        });
    }

    async sendMessage(conversationId: string, content: string, user: User) {
        const conversation = await this.conversationRepository.findOne({
            where: { id: conversationId },
            relations: ['application', 'application.campaign', 'application.campaign.brand', 'application.creator'],
        });

        if (!conversation) {
            throw new NotFoundException('Conversation not found');
        }

        const isBrand = conversation.application.campaign.brand.id === user.id;
        const isCreator = conversation.application.creator.id === user.id;

        if (!isBrand && !isCreator) {
            throw new ForbiddenException('Access denied');
        }

        const message = this.messageRepository.create({
            conversation,
            sender: user,
            content,
            type: MessageType.TEXT,
        });

        return this.messageRepository.save(message);
    }

    async createSystemMessage(conversation: Conversation, content: string, actionType?: string) {
        const message = this.messageRepository.create({
            conversation,
            content,
            type: MessageType.SYSTEM,
            actionType,
        });
        return this.messageRepository.save(message);
    }
}
