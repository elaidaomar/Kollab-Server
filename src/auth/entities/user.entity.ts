import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Unique,
  OneToOne,
  OneToMany,
} from 'typeorm';
import { UserRole } from '../enums/role.enum';
import { CreatorProfile } from './creator-profile.entity';
import { BrandProfile } from './brand-profile.entity';
import { Campaign } from '../../campaigns/entities/campaign.entity';
import { Application } from '../../campaigns/entities/application.entity';

import { Exclude } from 'class-transformer';

@Entity('users')
@Unique(['email', 'role'])
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Exclude()
  @Column()
  email: string;

  @Exclude()
  @Column({ select: false })
  password: string;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.CREATOR,
  })
  role: UserRole;

  // creator-profile.entity.ts
  @OneToOne(() => CreatorProfile, (profile) => profile.user, { cascade: true })
  creatorProfile: CreatorProfile;

  // brand-profile.entity.ts
  @OneToOne(() => BrandProfile, (profile) => profile.user, { cascade: true })
  brandProfile: BrandProfile;

  @OneToMany(() => Campaign, (campaign) => campaign.brand)
  campaigns: Campaign[];

  @OneToMany(() => Application, (application) => application.creator)
  applications: Application[];

  @Column({ nullable: true })
  name: string;

  @Column({ nullable: true })
  surname: string;

  @Exclude()
  @Column({ default: false })
  isEmailVerified: boolean;

  @Exclude()
  @Column({ default: false })
  isAdminApproved: boolean;

  @Exclude()
  @Column({ default: false })
  isAdminRejected: boolean;

  @Exclude()
  @Column({ type: 'varchar', length: 64, nullable: true, select: false })
  emailVerificationTokenHash: string | null;

  @Exclude()
  @Column({ type: 'timestamp', nullable: true, select: false })
  emailVerificationExpiresAt: Date | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
