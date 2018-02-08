module.exports = {
    ipAddress: '127.1.0.1',
    portNumber: 3000,
    user: 'db-user',
    database: 'db-name',
    password: 'db-password',
    host: 'db-server',
    storageFolder: process.cwd(),
    apiPrefix: '/api/',
    ignoreTables: {},
    connectionLimit: 10,
    passphrase: 'passphrase used to sign and verify tokens'
};
