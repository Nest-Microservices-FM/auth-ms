import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { envs } from 'src/config/envs';
import { rolesConfig } from './roles.config';

@Injectable()
export class ServiceJwt {
  constructor(private jwtService: JwtService) {}

  generateToken(role: string, userId: string) {
    const roleConfig = rolesConfig.find((config) => config.role === role);
    if (!roleConfig) {
      throw new Error(`Invalid role: ${role}`);
    }
    const payload = { role, userId };
    return this.jwtService.sign(payload, {
      expiresIn: roleConfig.expiresIn,
      secret: envs.jwtSecret,
    });
  }

  async verifyToken(token: string) {
    try {
      const payload = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });
      const roleConfig = rolesConfig.find((config) => config.role === payload.role);
      if (!roleConfig) {
        throw new UnauthorizedException('Invalid role');
      }
      return payload;
    } catch (error) {
      throw new UnauthorizedException('Invalid Token');
    }
  }
}