var mysql = null;

module.exports = {
    init: function(_mysql) {
	mysql = _mysql;
    },

    login: async function(login, password, callback) {
	let query = 'SELECT u.* FROM `cad_usuario` u LEFT OUTER JOIN `cad_cliente` c USING (`idcad_cliente`) WHERE u.email = ? AND u.senha = ? AND u.status = 1';
	let user = await mysql.exec(query, [login, password]);
	console.log(user);
	callback(user);
    }
};
