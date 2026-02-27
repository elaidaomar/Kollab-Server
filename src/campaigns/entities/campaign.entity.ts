import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    CreateDateColumn,
    UpdateDateColumn,
    ManyToOne,
    OneToMany,
} from 'typeorm';
import { BrandProfile } from '../../auth/entities/brand-profile.entity';
import { Application } from './application.entity';

export enum CampaignType {
    SOCIAL = 'Social',
    UGC = 'UGC',
}

export enum CampaignStatus {
    DRAFT = 'Draft',
    ACTIVE = 'Active',
    COMPLETED = 'Completed',
}

@Entity('campaigns')
export class Campaign {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column({
        type: 'enum',
        enum: CampaignType,
    })
    type: CampaignType;

    @Column()
    title: string;

    @Column('text')
    summary: string;

    @Column('timestamp')
    deadline: Date;

    @Column('text')
    brief: string;

    @Column('text')
    dos: string;

    @Column('text')
    donts: string;

    @Column('json')
    paymentDetails: {
        totalEarnings: number;
        breakdown: string;
    };

    @Column('text', { nullable: true })
    products: string;

    @Column('text', { nullable: true })
    inspiration: string;

    @Column('json')
    creatorCriteria: {
        locations: string[];
        gender: string;
        ageRange: string;
    };

    @Column('json')
    followerCriteria: {
        minFollowers: number;
    };

    @Column({
        type: 'enum',
        enum: CampaignStatus,
        default: CampaignStatus.DRAFT,
    })
    status: CampaignStatus;

    @ManyToOne(() => BrandProfile, (brand) => brand.campaigns)
    brand: BrandProfile;

    @OneToMany(() => Application, (application) => application.campaign)
    applications: Application[];

    @CreateDateColumn()
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;
}
