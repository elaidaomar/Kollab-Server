import { ValidationPipe, BadRequestException } from '@nestjs/common'
import { ValidationError } from 'class-validator'

export class AuthValidationPipe extends ValidationPipe {
  constructor(private readonly message: string = "Invalid operation") {
    super({
      whitelist: true, // strips unknown properties
      forbidNonWhitelisted: false, // throws on unknown properties
      transform: true, // auto-transform DTOs
      exceptionFactory: (errors: ValidationError[]) => {
        // Always return generic error, ignore all details
        return new BadRequestException(this.message)
      },
    })
  }
}
