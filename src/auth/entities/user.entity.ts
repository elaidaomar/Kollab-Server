import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn, UpdateDateColumn } from 'typeorm'
import { UserRole } from '../enums/role.enum'

@Entity('users')
export class User {
    @PrimaryGeneratedColumn('uuid')
    id: string

    @Column({ unique: true })
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

    @CreateDateColumn()
    createdAt: Date

    @UpdateDateColumn()
    updatedAt: Date
}
