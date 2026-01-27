import { Column, CreateDateColumn, Entity, ManyToOne, PrimaryGeneratedColumn } from 'typeorm'
import { User } from './user.entity'

@Entity('password_reset_tokens')
export class PasswordResetToken {
  @PrimaryGeneratedColumn('uuid')
  id: string

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  user: User

  @Column()
  tokenHash: string

  @Column()
  expiresAt: Date

  @Column({ type: 'timestamp', nullable: true })
  usedAt: Date | null

  @CreateDateColumn()
  createdAt: Date
}

