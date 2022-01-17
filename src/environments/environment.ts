export const environment = {
  production: false,
  http: {
    port: 30020,
    corsOrigin: ['http://localhost:4200'],
  },
  rpc: {
    servers: ['nats://localhost:3000'],
    queue: 'core-authentications',
  },
  db: {
    host: 'localhost',
    port: 3002,
    username: 'zozoboom',
    password: 'zozoboom',
    name: 'zozoboom',
  },
  cache: {
    host: 'localhost',
    port: 3003,
  },
  security: {
    emailAdminApprove: 'sllavvicc@gmail.com',
    approveCodeMinValue: 100000,
    approveCodeMaxValue: 999999,
    forgotTokenSalt: 'forgotTokenTTL',
    forgotTokenTTL: 3600,
    accessTokenSalt: 'accessTokenSalt',
    accessTokenTTL: 300,
    refreshTokenSalt: 'refreshTokenSalt',
    refreshTokenTTL: 864000,
  },
};
