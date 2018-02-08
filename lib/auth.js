var jwt = require('jsonwebtoken');
var config = require('../config');

module.exports = function(req, res, next) {
    var apikey = req.header('Authorization').replace('Bearer ', '');
    
    if (apikey) {
	jwt.verify(apikey, config.passphrase, (err, token) => {
	    console.log('err', err);
	    if (err)
		res.status(403).end('Unauthorized: ' + err.message + '\n');
	    else
		next();

	    console.log('tk', token);
	});
    } else
        res.status(403).end('Unauthorized: ' + err.message + '\n');
};
