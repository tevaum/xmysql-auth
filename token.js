var jwt = require('jsonwebtoken');
var config = require('./config');

var token = jwt.sign({origin: 'web-client', user: 'estevao'}, config.passphrase);
console.log(token);
