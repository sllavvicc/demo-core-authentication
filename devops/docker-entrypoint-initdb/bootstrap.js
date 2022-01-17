// Bootstrap main database
db = db.getSiblingDB(_getEnv('MONGO_DB_DATABASE'));
db.createUser({
  user: _getEnv('MONGO_DB_USERNAME'),
  pwd: _getEnv('MONGO_DB_PASSWORD'),
  roles: [{ role: 'readWrite', db: _getEnv('MONGO_DB_DATABASE') }],
  passwordDigestor: 'server',
});
