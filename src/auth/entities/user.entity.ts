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

    @Column({ unique: true })
    handle: string

    @Column({ nullable: true })
    firstName: string

    @Column({ nullable: true })
    lastName: string

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
