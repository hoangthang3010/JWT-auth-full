import {
  Controller,
  Post,
  Body,
  Req,
  Res,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import type { Response, Request } from 'express';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  @HttpCode(HttpStatus.NO_CONTENT)
  async signUp(
    @Body()
    body: {
      username: string;
      password: string;
      email: string;
      firstName: string;
      lastName: string;
    },
  ) {
    await this.authService.signUp(
      body.username,
      body.password,
      body.email,
      body.firstName,
      body.lastName,
    );
  }

  @Post('signin')
  async signIn(
    @Body() body: { username: string; password: string },
    @Res({ passthrough: false }) res: Response,
  ) {
    return this.authService.signIn(body.username, body.password, res);
  }

  @Post('signout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async signOut(
    @Req() req: Request,
    @Res({ passthrough: false }) res: Response,
  ) {
    const token = req.cookies?.refreshToken;
    await this.authService.signOut(token, res);
  }

  @Post('refresh')
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: false }) res: Response,
  ) {
    const token = req.cookies?.refreshToken;
    return this.authService.refresh(token, res);
  }
}
