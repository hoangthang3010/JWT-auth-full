import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class User extends Document {
  @Prop({ required: true, unique: true, trim: true, lowercase: true })
  username: string;

  @Prop({ required: true })
  hashedPassword: string;

  @Prop({ required: true, unique: true, lowercase: true, trim: true })
  email: string;

  @Prop({ required: true, trim: true })
  displayName: string;

  @Prop()
  avatarUrl?: string;

  @Prop()
  avatarId?: string;

  @Prop({ maxlength: 500 })
  bio?: string;

  @Prop({ sparse: true })
  phone?: string;
}

export const UserSchema = SchemaFactory.createForClass(User);
