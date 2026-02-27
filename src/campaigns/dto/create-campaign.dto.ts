import {
    IsString,
    IsEnum,
    IsNotEmpty,
    IsDateString,
    IsOptional,
    IsNumber,
    IsObject,
    ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { CampaignType } from '../entities/campaign.entity';

class PaymentDetailsDto {
    @IsNumber()
    @IsNotEmpty()
    totalEarnings: number;

    @IsString()
    @IsNotEmpty()
    breakdown: string;
}

class CreatorCriteriaDto {
    @IsString({ each: true })
    @IsNotEmpty({ each: true })
    locations: string[];

    @IsString()
    @IsNotEmpty()
    gender: string;

    @IsString()
    @IsNotEmpty()
    ageRange: string;
}

class FollowerCriteriaDto {
    @IsNumber()
    @IsNotEmpty()
    minFollowers: number;
}

export class CreateCampaignDto {
    @IsEnum(CampaignType)
    @IsNotEmpty()
    type: CampaignType;

    @IsString()
    @IsNotEmpty()
    title: string;

    @IsString()
    @IsNotEmpty()
    summary: string;

    @IsDateString()
    @IsNotEmpty()
    deadline: string;

    @IsString()
    @IsNotEmpty()
    brief: string;

    @IsString()
    @IsNotEmpty()
    dos: string;

    @IsString()
    @IsNotEmpty()
    donts: string;

    @IsObject()
    @ValidateNested()
    @Type(() => PaymentDetailsDto)
    paymentDetails: PaymentDetailsDto;

    @IsString()
    @IsOptional()
    products?: string;

    @IsString()
    @IsOptional()
    inspiration?: string;

    @IsObject()
    @ValidateNested()
    @Type(() => CreatorCriteriaDto)
    creatorCriteria: CreatorCriteriaDto;

    @IsObject()
    @ValidateNested()
    @Type(() => FollowerCriteriaDto)
    followerCriteria: FollowerCriteriaDto;
}
