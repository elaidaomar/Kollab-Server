import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    ManyToOne,
    CreateDateColumn,
} from 'typeorm';
import { Conversation } from './conversation.entity';
import { User } from '../../auth/entities/user.entity';

export enum MessageType {
    TEXT = 'text',
    SYSTEM = 'system',
    ACTION = 'action',
}

@Entity('messages')
export class Message {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @ManyToOne(() => Conversation, (conversation) => conversation.messages)
    conversation: Conversation;

    @ManyToOne(() => User)
    sender: User;

    @Column('text')
    content: string;

    @Column({
        type: 'enum',
        enum: MessageType,
        default: MessageType.TEXT,
    })
    type: MessageType;

    @Column({ nullable: true })
    actionType: string;

    @Column('json', { nullable: true })
    payload: any;

    @CreateDateColumn()
    createdAt: Date;
}
