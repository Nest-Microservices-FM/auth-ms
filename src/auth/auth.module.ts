import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { envs } from 'src/config';
import { ServiceJwt } from './jwt/jwt.service';

@Module({
  controllers: [AuthController],
  providers: [AuthService, ServiceJwt],
  imports:[
    JwtModule.register({
      global: true,
      secret: envs.jwtSecret,
    }),
  ]
})
export class AuthModule {}
