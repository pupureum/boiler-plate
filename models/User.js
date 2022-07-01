const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10 //saltRounds는 salt가 몇글자인지 나타낸다.
const jwt = require('jsonwebtoken');

const userSchema = mongoose.Schema({
	name: {
		type: String,
		maxlength: 50
	},
	email: {
		type: String,
		trim: true,
		unique: 1
	},
	password: {
		type: String,
		minlength: 3
	},
	lastname: {
		type: String,
		maxlength: 50
	},
	role: {
		type: Number,
		default: 0
	},
	image: String,
	token: {
		type: String
	},
	tokenExp: {
		type: Number
	}
})

userSchema.pre('save', function( next ){
	var user = this; //여기서 this는 userSchema로 적은 부분
	
	if(user.isModified('password')) {//비밀번호 바꿀때
		//비밀번호 암호화
		//Salt를 이용해서 암호화 해야하므로, salt를 getSalt로 먼저 생성해야한다.(saltRounds 필요)
		bcrypt.genSalt(saltRounds, function(err, salt){
			if(err) return next(err)
			bcrypt.hash(user.password, salt, function(err,hash) {
				if(err) return next(err)
				user.password = hash;
				next()
			})
		})
	} else {
		next()
	}
})

userSchema.methods.comparePassword = function(plainPassword, cb) {
	//plainPassword 1234 암호화된 비밀번호 $2b$10$USofeAzaJNuLCFItWF26ZO1dHBjziDP9pHHu/fH2OD6qDXzVbw9o6
	//plainPassword를 암호화해서 DB에 있는 비밀번호와 같은지 비교해야 한다.
	
	bcrypt.compare(plainPassword, this.password, function(err, isMatch) {
		if(err) return cb(err);
		cb(null, isMatch);
	})
}

userSchema.methods.generateToken = function(cb) {
	var user = this;
	//jsonwebtoken을 이용해서 token 생성하기
	var token = jwt.sign(user._id.toHexString(), 'secretToken') // user._id + 'secretToken' = token
	user.token = token
	user.save(function(err, user) {
		if(err) return cb(err)
		cb(null, user)
	})
}

userSchema.statics.findByToken = function(token, cb) {
	var user = this;
	//user._id + '' = token
	//토큰을 decode하여 유저아이디를 찾는다.
	jwt.verify(token, 'secretToken', function(err, decoded) {
		//유저 아이디를 이용해서 유저를 찾은 다음에
		//클라이언트에서 가져온 token과 DB에 보관된 토큰이 일치하는지 확인

		user.findOne({"_id": decoded, "token": token }, function(err, user){
			if(err) return cb(err)
			cb(null, user)
		})
	})
}

const User = mongoose.model('User', userSchema)

module.exports = { User }