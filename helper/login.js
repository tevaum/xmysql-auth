var mysql = null;

module.exports = {
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
	    let menu_access_sql = 'SELECT m.descricao as menu, sm.descricao as submenu, p.nivel as access from sys_menu_permissao p JOIN sys_submenu sm USING (idsys_submenu) JOIN sys_menu m USING (idsys_menu) WHERE idcad_usuario = ?';
	    let menu_access = await mysql.exec(menu_access_sql, [user.idcad_usuario]);

	    let api_access_sql = 'SELECT m.api_url as endpoint, p.nivel as access from sys_menu_permissao p JOIN sys_apimap m USING (idsys_submenu) WHERE idcad_usuario = ?';
	    let api_access = await mysql.exec(api_access_sql, [user.idcad_usuario]);
	    
	    callback({login: user.email, cache: {menu: menu_access, api: api_access}});
	} else {
	    callback({status: 'error', msg: 'Acesso negado.'});
	    return;	    
	}
    }
};
