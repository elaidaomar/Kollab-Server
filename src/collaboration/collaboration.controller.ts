import { Controller, Get, Post, Body, Param, UseGuards, Request, UseInterceptors, UploadedFile } from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { extname } from 'path';
import { CollaborationService } from './collaboration.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@Controller('collaboration')
@UseGuards(JwtAuthGuard)
export class CollaborationController {
    constructor(private readonly collaborationService: CollaborationService) { }

    @Get()
    async getCollaborations(@Request() req) {
        return this.collaborationService.findAllForUser(req.user);
    }

    @Get('application/:id')
    async getConversationByApplication(@Param('id') applicationId: string, @Request() req) {
        return this.collaborationService.getOrCreateConversation(applicationId, req.user);
    }

    @Get(':id/messages')
    async getMessages(@Param('id') conversationId: string, @Request() req) {
        return this.collaborationService.getMessages(conversationId, req.user);
    }

    @Post(':id/messages')
    async sendMessage(@Param('id') id: string, @Body('content') content: string, @Request() req) {
        return this.collaborationService.sendMessage(id, content, req.user);
    }

    @Post(':id/actions')
    async sendAction(@Param('id') id: string, @Body() body: { content: string, actionType: string, payload: any }, @Request() req) {
        return this.collaborationService.sendActionMessage(id, body.content, body.actionType, body.payload, req.user);
    }

    @Post(':id/upload')
    @UseInterceptors(FileInterceptor('file', {
        storage: diskStorage({
            destination: './public/uploads',
            filename: (req, file, cb) => {
                const randomName = Array(32).fill(null).map(() => (Math.round(Math.random() * 16)).toString(16)).join('');
                return cb(null, `${randomName}${extname(file.originalname)}`);
            }
        })
    }))
    async uploadFile(@UploadedFile() file: any) {
        return {
            url: `/uploads/${file.filename}`,
            filename: file.filename,
            originalname: file.originalname,
            mimetype: file.mimetype,
            size: file.size
        };
    }
}
