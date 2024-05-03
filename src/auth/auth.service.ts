import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException, Payload } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { RegisterUserDto } from './dto/register-user.dto';
import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';
import { ServiceJwt } from './jwt/jwt.service';
import { rolesConfig } from './jwt/roles.config';


@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit{

  private readonly logger = new Logger('AuthService')

  constructor(
    private jwtService: ServiceJwt
  ){
    super();
  }


  onModuleInit(){
    this.$connect();
    this.logger.log('MongoDB connected')
  }

  // HERE GOES THE LOGIC FOR REGISTER, LOGIN AND TOKEN VERIFICATION //

  async verifyToken(token: string) {
    try {
      const payload = await this.jwtService.verifyToken(token);
      const user = await this.user.findUnique({
        where: { id: payload.userId },
        select: { id: true, email: true, role: true },
      });
  
      if (!user) {
        throw new RpcException({
          status: 401,
          message: 'User not found',
        });
      }
  
      const roleConfig = rolesConfig.find((config) => config.role === user.role);
      const newToken = await this.jwtService.generateToken(user.role, user.id);
  
      return { user, token: newToken, roleConfig };
    } catch (error) {
      throw new RpcException({ status: 401, message: 'Invalid Token' });
    }
  }


  async registerUser(registerUserDto: RegisterUserDto) {
    try {
      const { name, email, password, role } = registerUserDto;
      const user = await this.user.findUnique({
        where: { email },
      });

      if (user) {
        throw new RpcException({
          status: 400,
          message: 'User already exists',
        });
      }

      const newUser = await this.user.create({
        data: {
          email,
          password: bcrypt.hashSync(password, 10),
          name,
          role,
        },
      });

      const { password: _, ...rest } = newUser;
      const token = await this.jwtService.generateToken(newUser.role, newUser.id);

      return { user: rest, token };
    } catch (error) {
      throw new RpcException({ status: 400, message: error.message });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    try {
      const { email, password } = loginUserDto;
      const user = await this.user.findUnique({
        where: { email },
      });

      if (!user) {
        throw new RpcException({
          status: 400,
          message: 'User/Password not valid',
        });
      }

      const isPasswordValid = bcrypt.compareSync(password, user.password);
      if (!isPasswordValid) {
        throw new RpcException({
          status: 400,
          message: 'User/Password not valid',
        });
      }

      const { password: _, ...rest } = user;
      const token = await this.jwtService.generateToken(user.role, user.id);

      return { user: rest, token };
    } catch (error) {
      throw new RpcException({ status: 400, message: error.message });
    }
  }
}
