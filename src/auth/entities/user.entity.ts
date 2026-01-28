import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn, UpdateDateColumn, Unique } from 'typeorm'
import { UserRole } from '../enums/role.enum'

@Entity('users')
@Unique(['email', 'role'])
export class User {
    @PrimaryGeneratedColumn('uuid')
    id: string

    @Column()
    email: string

    @Column({ select: false })
    password: string

    @Column({
        type: 'enum',
        enum: UserRole,
        default: UserRole.CREATOR,
    })
    role: UserRole

    @Column({ nullable: true })
    name: string

    @Column({ nullable: true })
    surname: string

    @Column({ default: false })
    isEmailVerified: boolean

    @Column({ type: 'varchar', length: 64, nullable: true })
    emailVerificationTokenHash: string | null

    @Column({ type: 'timestamp', nullable: true })
    emailVerificationExpiresAt: Date | null

    @CreateDateColumn()
    createdAt: Date

    @UpdateDateColumn()
    updatedAt: Date
}
