const { User } = require('../models/User');

let auth = (req, res, next) => {
	//인증 처리 하는 곳
	
	//클라이언트 쿠키에서 토큰을 가져온다.
	let token = req.cookies.x_auth;

	//Token을 복호화 한 후, 유저를 찾는다.
	User.findByToken(token, (err, user) => {
		if(err) throw err;
		if(!user) return res.json({isAuth: false, error: true })

		req.token = token;
		req.user = user; //index.js에서 req.token 이런식으로 정보 가지기 위해서
		next(); //미들웨어에서 갇히지 않고 넘어갈 수 있게
	})

	//유저가 있으면 인증 OK, 없으면 NO

}

module.exports = { auth };