import { Column, Entity, JoinColumn, OneToOne, PrimaryGeneratedColumn } from "typeorm"
import { User } from "./user.entity"

@Entity('brand_profiles')
export class BrandProfile {
  @PrimaryGeneratedColumn('uuid')
  id: string

  @OneToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn()
  user: User

  @Column()
  company: string
}
