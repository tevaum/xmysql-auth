var jwt = require('jsonwebtoken');
var config = require('../config');
var body_parser = require('body-parser');

var auth_cache = {};

var xapi = null;
var LoginHelper = null;

var AuthPlugin = function(_xapi, _login) {
    xapi = _xapi;
    LoginHelper = _login;

    // Initialize helper with database access
    LoginHelper.init(xapi.mysql);

    xapi.app.post(config.apiPrefix + 'login', body_parser.json(), AuthPlugin.login);
};

AuthPlugin._has_access = function(login, uri) {
    let access = auth_cache[login].api;

    let has_access = access.filter((item) => {
	return item.endpoint == uri.replace('/api/', '');
    }).length;

    console.log('[AccessControl]', login, '=>', uri + ':', has_access ? 'granted' : 'DENIED');

    return has_access;
};

AuthPlugin.login = function (req, res, next) {
    LoginHelper.login(req.body.login, req.body.password, (user) => {
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

AuthPlugin.authn = function(req, res, next) {
    // Enable login and prefetch without authorization for Chrome (also in authz)
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
	    if (err) {
		console.error('Token Error:', err);
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
		//console.log('[AuthN] Decoded token:', token);
		req.token = token;
		next();
	    }
	});
    } else {
	// if no apikey, return with unautorized
        res.status(403).json({status: 'error', msg: 'Unauthorized: ' + err.message + '\n'});
    }
};

AuthPlugin.authz = function(req, res, next) {
    // Enable login and prefetch without authorization for Chrome (also in authn)
    if (req.method == 'OPTIONS' || req.path == '/api/login') {
	console.log('API Request:', req.path);
	next();
	return;
    }

    if (!auth_cache.hasOwnProperty(req.token.sub)) {
	// recache auth data
	LoginHelper.access(req.token.sub, (login, access) => {
	    console.log('[AuthZ] Recaching access data for', req.token.sub);
	    auth_cache[login] = access;

	    if (!AuthPlugin._has_access(req.token.sub, req.path)) {
		res.status(403).json({status: 'error', msg: 'Unauthorized: no access.\n'});
		return;
	    }
	    next();
	});
    } else {
	if (!AuthPlugin._has_access(req.token.sub, req.path)) {
	    res.status(403).json({status: 'error', msg: 'Unauthorized: no access.\n'});
	    return;
	}
	next();
    }
};

module.exports = AuthPlugin;
