import { Logger, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import {
  FastifyAdapter,
  NestFastifyApplication
} from '@nestjs/platform-fastify';
import { LoggingInterceptor } from '@zozoboom/core/backend/interceptor';
import { QueryStringToObjectPipe } from '@zozoboom/core/backend/pipe';
import * as cluster from 'cluster';
import fastifyCookie from 'fastify-cookie';
import * as os from 'os';
import { AppModule } from './app/app.module';
import { environment } from './environments/environment';

/** Bootstrap configuration */
async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter(),
    {
      cors: {
        origin: environment.http.corsOrigin,
        credentials: true,
      },
    }
  );
  app.useGlobalPipes(
    new QueryStringToObjectPipe(),
    new ValidationPipe({
      transform: true,
      transformOptions: {
        strategy: 'excludeAll',
        exposeUnsetFields: false,
      },
      whitelist: true,
      forbidNonWhitelisted: true,
      forbidUnknownValues: true,
    })
  );
  app.useGlobalInterceptors(new LoggingInterceptor());
  app.connectMicroservice<MicroserviceOptions>(
    {
      transport: Transport.NATS,
      options: {
        servers: environment.rpc.servers,
        queue: environment.rpc.queue,
        waitOnFirstConnect: true,
        debug: false
      },
    },
    { inheritAppConfig: true }
  );
  app.register(fastifyCookie);
  app.startAllMicroservices();
  await app.listen(environment.http.port, '0.0.0.0');
}

/** Cluster configuration */
switch (environment.production) {
  case true:
    if (cluster.isMaster) {
      const cpuCount = os.cpus().length;
      for (let i = 0; i < cpuCount; i += 1) {
        cluster.fork();
      }
      cluster.on('online', (worker) => {
        Logger.log('Worker ' + worker.process.pid + ' is online.');
      });
      cluster.on('exit', ({ process }) => {
        Logger.log('worker ' + process.pid + ' died.');
      });
    } else {
      bootstrap();
    }
    break;
  case false:
    bootstrap();
    break;
}