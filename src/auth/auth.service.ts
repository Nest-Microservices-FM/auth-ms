import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { RegisterUserDto } from './dto/register-user.dto';
import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';
@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit{

  private readonly logger = new Logger('AuthService')


  onModuleInit(){
    this.$connect();
    this.logger.log('MongoDB connected')
  }


  async registerUser(registerUserDto:RegisterUserDto){
    try {
      const {name, email, password} = registerUserDto;
      const user = await this.user.findUnique({
        where:{
          email: email,

        }
      });

    if( user ){
      throw new RpcException({ 
        status:400,
        message: 'User already exists'
      })
    }

    const newUser = await this.user.create({
      data: {
        email: email,
        password: bcrypt.hashSync(password, 10),
        name: name
      }
    })

    const { password: __, ...rest } = newUser
    return {
      user: rest, 
      token: 'ABC'
    }
    } catch (error) {
      throw new RpcException({
        status:400,
        message: error.message
      })
    }
  }

  async loginUser(loginUserDto:LoginUserDto){
    try {
      const {email, password} = loginUserDto;
      
      const user = await this.user.findUnique({
        where:{
          email: email,

        }
      });

      if( !user ){
        throw new RpcException({ 
          status:400,
          message: 'User/Password not valid'
        })
      }

      const isPasswordValid = bcrypt.compareSync(password, user.password)
      if( !isPasswordValid){
        throw new RpcException({
          status: 400,
          message: 'User/Password not valid'
        })
      }

      const { password: __, ...rest } = user;
      return {
        user: rest, 
        token: 'ABC'
      }
    } catch (error) {
      throw new RpcException({
        status:400,
        message: error.message
      })
    }
  }
}
