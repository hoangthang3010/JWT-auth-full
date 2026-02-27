import { MongooseModule } from '@nestjs/mongoose';
import { ConfigService } from '@nestjs/config';

function addTimeoutToUri(uri: string | undefined): string | undefined {
  if (!uri) return uri;
  const params = 'connectTimeoutMS=10000&serverSelectionTimeoutMS=10000';
  return uri.includes('?') ? `${uri}&${params}` : `${uri}?${params}`;
}

export const DatabaseModule = MongooseModule.forRootAsync({
  useFactory: (configService: ConfigService) => ({
    uri: addTimeoutToUri(configService.get<string>('MONGODB_CONNECTIONSTRING')),
  }),
  inject: [ConfigService],
});
