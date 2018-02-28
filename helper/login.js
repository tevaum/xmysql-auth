var mysql = null;

var Login = {
    init: function(_mysql) {
	mysql = _mysql;
    },

    login: async function(login, password, callback) {
	let query = 'SELECT u.*, c.status as cliente_status FROM `cad_usuario` u LEFT OUTER JOIN `cad_cliente` c USING (`idcad_cliente`) WHERE u.email = ? AND u.senha = ? AND u.status = 1';
	let user = await mysql.exec(query, [login, password]);

	user = user.shift();
	if (!user) {
	    callback({status: 'error', msg: 'Usuário ou senha inválidos.'});
	    return;
	} else if (user.adm_global == 1  || (user.adm_local == 1 && user.cliente_status == 1)) {
	    Login.access(user.email, (login, access_data) => {
		console.log('[Login] Access data for', login, 'retrieved.');
		callback({login: user.email, cache: access_data});
	    });

	} else {
	    callback({status: 'error', msg: 'Acesso negado.'});
	    return;	    
	}
    },

    access: async function(login, callback) {
	let menu_access_sql = 'SELECT m.descricao as menu, sm.descricao as submenu, p.nivel as access from sys_menu_permissao p JOIN sys_submenu sm USING (idsys_submenu) JOIN sys_menu m USING (idsys_menu) JOIN cad_usuario u USING (idcad_usuario) WHERE u.email = ?';
	let menu_access = await mysql.exec(menu_access_sql, [login]);

	let api_access_sql = 'SELECT m.api_url as endpoint, p.nivel as access from sys_menu_permissao p JOIN sys_apimap m USING (idsys_submenu) JOIN cad_usuario u USING (idcad_usuario) WHERE u.email = ?';
	let api_access = await mysql.exec(api_access_sql, [login]);

	callback(login, {menu: menu_access, api: api_access});
    }
};

module.exports = Login;
