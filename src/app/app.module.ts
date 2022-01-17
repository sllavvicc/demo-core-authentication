import {
  CacheModule,
  CACHE_MANAGER,
  Inject,
  Module,
  OnModuleInit
} from '@nestjs/common';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { MongooseModule } from '@nestjs/mongoose';
import { ScheduleModule } from '@nestjs/schedule';
import {
  AuthenticationsAccessCollection,
  AuthenticationsAccessSchema,
  AuthenticationsApproveCollection,
  AuthenticationsApproveSchema,
  AuthenticationsForgotCollection,
  AuthenticationsForgotSchema
} from '@zozoboom/core-authentications/backend/schema';
import { Cache } from 'cache-manager';
import * as redisStore from 'cache-manager-redis-store';
import { environment } from '../environments/environment';
import { RepositoryService } from './repository.service';
import { RpcController } from './rpc.controller';
import { SecurityService } from './security.service';
import { AdminV1Controller } from './v1/admin-v1.controller';
import { PublicV1Controller } from './v1/public-v1.controller';

@Module({
  imports: [
    MongooseModule.forRoot(
      `mongodb://${environment.db.username}:${environment.db.password}@${environment.db.host}:${environment.db.port}/${environment.db.name}`,
      {
        useNewUrlParser: true,
        autoIndex: true,
      }
    ),
    MongooseModule.forFeature([
      {
        name: AuthenticationsAccessCollection.name,
        schema: AuthenticationsAccessSchema,
      },
      {
        name: AuthenticationsApproveCollection.name,
        schema: AuthenticationsApproveSchema,
      },
      {
        name: AuthenticationsForgotCollection.name,
        schema: AuthenticationsForgotSchema,
      },
    ]),
    ClientsModule.registerAsync([
      {
        name: 'RPC_SERVICE',
        useFactory: () => {
          return {
            transport: Transport.NATS,
            options: {
              servers: environment.rpc.servers,
              waitOnFirstConnect: true,
              debug: false
            },
          };
        },
      },
    ]),
    CacheModule.register({
      store: redisStore,
      host: environment.cache.host,
      port: environment.cache.port,
    }),
    ScheduleModule.forRoot(),
  ],
  controllers: [RpcController, AdminV1Controller, PublicV1Controller],
  providers: [RepositoryService, SecurityService],
})
export class AppModule implements OnModuleInit {
  constructor(@Inject(CACHE_MANAGER) private _cacheService: Cache) { }
  onModuleInit(): void {
    this._cacheService.reset();
  }
}
