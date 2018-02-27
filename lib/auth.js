var jwt = require('jsonwebtoken');
var config = require('../config');
var body_parser = require('body-parser');

var auth_cache = {};

var AuthPlugin = function (xapi, login) {
    this.xapi = xapi;
    this.login_helper = login;

    login.init(xapi.mysql);

    xapi.app.post(config.apiPrefix + 'login', body_parser.json(), this.login());
};

AuthPlugin.prototype.login = function() {
    var do_login = this.login_helper.login;

    return function (req, res, next) {
	do_login(req.body.login, req.body.password, (user) => {
	    if (user.hasOwnProperty('login')) {
		console.log('user to create token for:', user.login);

		if (user.hasOwnProperty('cache')) {
		    auth_cache[user.login] = user.cache;
		    delete user.cache;
		}

	    	let token = jwt.sign({}, config.passphrase, {expiresIn: '1h', audience: 'compras-api', issuer: 'compras-api', subject: user.login});
		user.token = {type: 'Bearer', value: token};
		user.status = 'success';
		user.menu = auth_cache[user.login].menu;
	    }

	    res.json(user);
	});
    };
};

AuthPlugin.authn = function() {
    return function(req, res, next) {
	// Enable login and prefetch without authorization for Chrome
	if (req.method == 'OPTIONS' || req.path == '/api/login') {
	    console.log('API Request:', req.path);
	    next();
	    return;
	}

	//Check for authorization header
	var auth = req.header('Authorization');
	if (!auth) {
	    res.status(403).json({status: 'error', msg: 'Unauthorized.\n'});
	    return;
	}

	// Retrieve apikey
	var apikey = auth.replace('Bearer ', '');
	if (apikey) {
	    // Verify if apikey is a valid token
	    jwt.verify(apikey, config.passphrase, (err, token) => {
		console.error('Token Error:', err);
		if (err) {
		    // If token is expired, clear the cached data for the user
		    if (err.name == 'TokenExpiredError') {
			let tk = jwt.decode(apikey);
			if (auth_cache.hasOwnProperty(tk.login)) {
			    console.log('Removing cached data for', tk.sub);
			    delete auth_cache[tk.sub];
			}
		    }
		    res.status(403).json({status: 'error', msg: 'Unauthorized: ' + err.message + '\n'});
		} else {
		    // Put the parsed token in the request and continue if token is valid
		    console.log('[AuthN] Decoded token:', token);
		    req.token = token;
		    next();
		}
	    });
	} else {
	    // if no apikey, return with unautorized
            res.status(403).json({status: 'error', msg: 'Unauthorized: ' + err.message + '\n'});
	}
    };
};

AuthPlugin.authz = function() {
    //let do_access = this.login_helper.access;

    return function(req, res, next) {
	console.log('APP:', req.app);
	// Enable login and prefetch without authorization for Chrome
	if (req.method == 'OPTIONS' || req.path == '/api/login') {
	    console.log('API Request:', req.path);
	    next();
	    return;
	}

	console.log('[AuthZ] User:', req.token.sub);
	if (!auth_cache.hasOwnProperty(req.token.sub)) {
	    // recache auth data
	    do_access(req.token.sub, (login, access) => {
		auth_cache[login] = access;
		console.log('[AuthZ] Recache Access:', auth_cache[login]);
	    });
	} else {
	    let access = auth_cache[req.token.sub];
	    console.log('[AuthZ] Access:', auth_cache[req.token.sub]);
	    next();
	}
    };
};

module.exports = AuthPlugin;
