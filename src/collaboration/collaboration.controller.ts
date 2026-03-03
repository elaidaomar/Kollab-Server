import { Controller, Get, Post, Body, Param, UseGuards, Request } from '@nestjs/common';
import { CollaborationService } from './collaboration.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@Controller('collaboration')
@UseGuards(JwtAuthGuard)
export class CollaborationController {
    constructor(private readonly collaborationService: CollaborationService) { }

    @Get('application/:id')
    async getConversationByApplication(@Param('id') applicationId: string, @Request() req) {
        return this.collaborationService.getOrCreateConversation(applicationId, req.user);
    }

    @Get(':id/messages')
    async getMessages(@Param('id') conversationId: string, @Request() req) {
        return this.collaborationService.getMessages(conversationId, req.user);
    }

    @Post(':id/messages')
    async sendMessage(
        @Param('id') conversationId: string,
        @Body('content') content: string,
        @Request() req,
    ) {
        return this.collaborationService.sendMessage(conversationId, content, req.user);
    }
}
