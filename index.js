const express = require('express')
const app = express()
const port = 5000
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const config = require('./config/key');
const { auth } = require('./middileware/auth');
const { User } = require('./models/User');

//application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({extended: true}));

//application/json
app.use(bodyParser.json());
app.use(cookieParser());

const mongoose = require('mongoose')
mongoose.connect(config.mongoURI, {
	useNewUrlParser: true, useUnifiedTopology: true//, useCreateIndex: true//, useFindAndModify: false
}).then(() => console.log('MongoDB Connected...'))
  .catch(err => console.log(err))


app.get('/', (req, res) => res.send('Hello World!'))

app.post('/api/users/register', (req, res) => {

	//회원가입 필요할 때 필요한 정보들을 client에서 가져오면 DB에 넣어준다
	const user = new User(req.body)

	user.save((err, userInfo) => { //mongodb에서 오는 method save로 user model에 저장
		//console.log(err);
		if(err) return res.json({success: false, err})
		return res.status(200).json({
			success: true
		})
	})
})

app.post('/api/users/login', (req, res) => {
	//요청된 이메일을 DB에서 있는지 찾는다.
	User.findOne({ email: req.body.email }, (err, user) => {
		if(!user) {
			return res.json({
				loginSuccess: false,
				message: "제공된 이메일에 해당하는 유저가 없습니다."
			})
		}
	//console.log(user)
	//요청한 이메일이 DB에 있다면 비밀번호가 맞는지 확인.
	user.comparePassword(req.body.password, (err, isMatch) => {
		//console.log('err',err)
		//console.log('isMatch',isMatch)
		if(!isMatch)
			return res.json({ loginSuccess: false, message: "비밀번호가 틀렸습니다." })
			
		//비밀번호까지 맞다면 그 유저를 위한 토큰을 생성하기.
		user.generateToken((err, user) => {
			if(err) return res.status(400).send(err);
			// 토큰을 저장한다. (쿠키, 로컬스토리지 등등에..)
			res.cookie("x_auth", user.token)
				.status(200)
				.json({ loginSuccess: true, userId: user._id })
			})
		})
	})
})

//Auth route : 페이지 이동할때마다 로그인 되어있는지 안되어있는지, 관리자 유저인지 등을 체크하기 위해서,
			// 글을 쓸때나 지울때 권한이 있는지 같은것도 체크.
app.get('/api/users/auth', auth, (req, res) => {
	//여기까지 미들웨어를 통과해 왔다는 얘기는 Authentication이 True라는 말.
	res.status(200).json({
		_id: req.user._id,
		isAdmin: req.user.role === 0 ? false : true, //role 0 -> 일반유저, 0 아니면 관리자
		isAuth: true,
		email: req.user.email,
		name: req.user.name,
		lastname: req.user.lastname,
		role: req.user.role,
		image: req.user.image
	})
})

app.get('/api/users/logout', auth, (req, res) => {
	User.findOneAndUpdate({ _id: req.user._id},
		{ token: "" },
		(err, user) => {
			if(err) return res.json({ success:false, err });
			return res.status(200).send({
				seccess: true
			})
		})
})

app.listen(port, () => console.log(`Example app listening on port ${port}!`) )
