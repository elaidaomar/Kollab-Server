import { Column, Entity, JoinColumn, OneToOne, PrimaryGeneratedColumn } from "typeorm"
import { User } from "./user.entity"

@Entity('creator_profiles')
export class CreatorProfile {
  @PrimaryGeneratedColumn('uuid')
  id: string

  @OneToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn()
  user: User

  @Column({ unique: true })
  handle: string
}
