import {
  Injectable,
  ConflictException,
  BadRequestException,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import * as crypto from 'crypto';
import { Response } from 'express';
import { User } from '../schemas/user.schema';
import { Session } from '../schemas/session.schema';

const ACCESS_TOKEN_TTL = '2m';
const REFRESH_TOKEN_TTL = 14 * 24 * 60 * 60 * 1000; // 14 ngày

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    @InjectModel(Session.name) private sessionModel: Model<Session>,
  ) {}

  async signUp(
    username: string,
    password: string,
    email: string,
    firstName: string,
    lastName: string,
  ): Promise<void> {
    if (!username || !password || !email || !firstName || !lastName) {
      throw new BadRequestException(
        'Không thể thiếu username, password, email, firstName, và lastName',
      );
    }

    const duplicate = await this.userModel.findOne({ username });
    if (duplicate) {
      throw new ConflictException('username đã tồn tại');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await this.userModel.create({
      username,
      hashedPassword,
      email,
      displayName: `${firstName} ${lastName}`,
    });
  }

  async signIn(
    username: string,
    password: string,
    res: Response,
  ): Promise<void> {
    if (!username || !password) {
      throw new BadRequestException('Thiếu username hoặc password.');
    }

    const user = await this.userModel.findOne({ username });
    if (!user) {
      throw new UnauthorizedException('username hoặc password không chính xác');
    }

    const passwordCorrect = await bcrypt.compare(password, user.hashedPassword);
    if (!passwordCorrect) {
      throw new UnauthorizedException('username hoặc password không chính xác');
    }

    const accessToken = jwt.sign(
      { userId: user._id },
      process.env.ACCESS_TOKEN_SECRET!,
      { expiresIn: ACCESS_TOKEN_TTL },
    );

    const refreshToken = crypto.randomBytes(64).toString('hex');

    await this.sessionModel.create({
      userId: user._id,
      refreshToken,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL),
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: REFRESH_TOKEN_TTL,
    });

    res.status(200).json({
      message: `User ${user.displayName} đã logged in!`,
      accessToken,
    });
  }

  async signOut(
    refreshToken: string | undefined,
    res: Response,
  ): Promise<void> {
    if (refreshToken) {
      await this.sessionModel.deleteOne({ refreshToken });
      res.clearCookie('refreshToken');
    }
    res.sendStatus(204);
  }

  async refresh(
    refreshToken: string | undefined,
    res: Response,
  ): Promise<void> {
    if (!refreshToken) {
      throw new UnauthorizedException('Token không tồn tại.');
    }

    const session = await this.sessionModel.findOne({ refreshToken });
    if (!session) {
      throw new ForbiddenException('Token không hợp lệ hoặc đã hết hạn');
    }

    if (session.expiresAt < new Date()) {
      throw new ForbiddenException('Token đã hết hạn.');
    }

    const newRefreshToken = crypto.randomBytes(64).toString('hex');
    session.refreshToken = newRefreshToken;
    session.expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL);
    await session.save();

    const accessToken = jwt.sign(
      { userId: session.userId },
      process.env.ACCESS_TOKEN_SECRET!,
      { expiresIn: ACCESS_TOKEN_TTL },
    );

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: REFRESH_TOKEN_TTL,
    });

    res.status(200).json({ accessToken });
  }
}
