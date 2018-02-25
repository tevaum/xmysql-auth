var jwt = require('jsonwebtoken');
var config = require('../config');
var body_parser = require('body-parser');

var AuthPlugin = function (xapi, login) {
    this.xapi = xapi;
    this.login_helper = login;

    login.init(xapi.mysql);

    xapi.app.post(config.apiPrefix + 'login', body_parser.json(), this.login())
};

AuthPlugin.prototype.login = function() {
    var do_login = this.login_helper.login;

    return function (req, res, next) {
	do_login(req.body.login, req.body.password, (user) => {
	    res.json(user);
	});
	
    }
};

AuthPlugin.access = function() {
    return function(req, res, next) {
	if (req.method == 'OPTIONS' || req.path == '/api/login') {
	    // Enable login and prefetch without authorization for Chrome
	    console.log(req.path);
	    next();
	    return;
	}

	var auth = req.header('Authorization');

	if (!auth) {
	    res.status(403).end('Unauthorized.\n');
	    return;
	}

	var apikey = auth.replace('Bearer ', '');
	
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
};


module.exports = AuthPlugin;
