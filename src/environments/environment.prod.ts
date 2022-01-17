export const environment = {
  production: true,
  http: {
    port: parseInt(process.env.HTTP_PORT, 10),
    corsOrigin: process.env.HTTP_CORS_ORIGIN.split(','),
  },
  rpc: {
    servers: process.env.RPC_SERVERS.split(','),
    queue: process.env.RPC_QUEUE,
  },
  db: {
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT, 10),
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    name: process.env.DB_NAME,
  },
  cache: {
    host: process.env.CACHE_HOST,
    port: parseInt(process.env.CACHE_PORT, 10),
  },
  security: {
    emailAdminApprove: process.env.SECURITY_EMAIL_ADMIN_APPROVE,
    approveCodeMinValue: 100000,
    approveCodeMaxValue: 999999,
    forgotTokenSalt: process.env.SECURITY_FORGOT_TOKEN_SALT,
    forgotTokenTTL: 3600,
    accessTokenSalt: process.env.SECURITY_ACCESS_TOKEN_SALT,
    accessTokenTTL: 300,
    refreshTokenSalt: process.env.SECURITY_REFRESH_TOKEN_SALT,
    refreshTokenTTL: 864000,
  },
};
