import { Injectable, UnauthorizedException, ConflictException } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { InjectRepository } from '@nestjs/typeorm'
import { Repository } from 'typeorm'
import * as bcrypt from 'bcrypt'
import { User } from './entities/user.entity'
import { SignupDto } from './dto/signup.dto'
import { UserRole } from './enums/role.enum'

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private jwtService: JwtService
  ) { }

  async login(user: any) {
    const payload = { sub: user.id, email: user.email }

    return {
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
      },
      token: this.jwtService.sign(payload),
    }
  }

  async validateUser(email: string, password: string) {
    const user = await this.userRepository.findOne({
      where: { email },
      select: ['id', 'email', 'password', 'firstName', 'lastName', 'role'],
    })

    if (!user || !user.password) throw new UnauthorizedException('Invalid credentials')

    const match = await bcrypt.compare(password, user.password)
    if (!match) throw new UnauthorizedException('Invalid credentials')

    return user
  }

  async signup(data: SignupDto) {
    const existing = await this.findUserByEmail(data.email)
    if (existing) throw new ConflictException('Email already exists')

    const hashed = await bcrypt.hash(data.password, 10)
    const user = await this.createUser({ ...data, password: hashed })

    return this.login(user)
  }

  async findUserByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } })
  }

  async createUser(data: any): Promise<User> {
    const user = this.userRepository.create(data as User)
    return this.userRepository.save(user)
  }
}
