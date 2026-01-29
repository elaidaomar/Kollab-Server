import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn, UpdateDateColumn, Unique, OneToOne } from 'typeorm'
import { UserRole } from '../enums/role.enum'
import { CreatorProfile } from './creator-profile.entity'
import { BrandProfile } from './brand-profile.entity'

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

    // creator-profile.entity.ts
    @OneToOne(() => CreatorProfile, (profile) => profile.user, { cascade: true })
    creatorProfile: CreatorProfile

    // brand-profile.entity.ts
    @OneToOne(() => BrandProfile, (profile) => profile.user, { cascade: true })
    brandProfile: BrandProfile

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
