import { Injectable, UnauthorizedException } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import * as bcrypt from 'bcrypt'

@Injectable()
export class AuthService {
  constructor(private jwtService: JwtService) {}

  async login(user: any) {
    const payload = { sub: user.id, email: user.email }

    return {
      user,
      token: this.jwtService.sign(payload),
    }
  }

  async validateUser(email: string, password: string) {
    // fetch user from DB
    const user = await this.findUserByEmail(email)
    if (!user || !user.password) throw new UnauthorizedException()

    const match = await bcrypt.compare(password, user.password)
    if (!match) throw new UnauthorizedException()

    return user
  }

  async signup(data: any) {
    const hashed = await bcrypt.hash(data.password, 10)
    const user = await this.createUser({ ...data, password: hashed })

    return this.login(user)
  }

  // ⬇️ mock methods (replace with real DB logic)
  async findUserByEmail(email: string): Promise<{ id: string; email: string; password: string } | null> {
    // Replace this mock implementation with actual database logic
    return null
  }

  async createUser(data: any) {
    return data
  }
}
