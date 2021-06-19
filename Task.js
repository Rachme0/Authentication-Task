const express = require('express');
const session = require('express-session');
const hbs = require('express-handlebars');
const mongoose = require('mongoose');
const passport = require('passport')
const localStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const Task = express();


mongoose.connect("mongodb://localhost:27017/node-auth-Task",{
    useNewUrlParser: true,
    useUnifiedTopology: true
});

const UserSchema = new mongoose.Schema({
    username:{
        type:String,
        required:true
    },
    password:{
        type:String,
        required:true
    }
});

const User = mongoose.model('User',UserSchema);


//works as middleware

Task.engine('hbs',hbs({extname: '.hbs'}));
Task.set('view engine','hbs');
Task.use(express.static(__dirname + '/public'));
Task.use(session({
    secret:"verygoodsecrets",
    resave: false,
    saveUninitialized: true
}));
Task.use(express.urlencoded({extended:false}));
Task.use(express.json());


//passport.js
Task.use(passport.initialize());
Task.use(passport.session());

passport.serializeUser(function(user,done){
    done(null,user.id);

});

passport.deserializeUser(function(id,done){
    user.FindId(id,function(err,user){
        done(err,user);
    });
});

passport.use(new localStrategy(function(username,password,done){
    user.findOne({username:username},function(err,user){
        if(err) return done(err);
        if(!user) return done(null,false,{message: 'username Incorrect!!'});

        bcrypt.compare(password, user.password, function(err,res){
            if (err) return done(err);
            if(res == false) return done(null,false, {message: 'password Incorrect'});

            return done(null,user);
            
        });
    });
}));

function isLoggedIn(req, res, next){
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}
function isLoggedOut(req, res ,next){
    if (!req.isAuthenticated()) return next();
    res.redirect('/');
}

//Routes
Task.get('/', (req, res) => {
    res.render("index",{title: "Home"});
});

Task.get('/about', (req,res) => {
    res.render('index',{title:"About"});

});

Task.get('/login', isLoggedOut, (req, res) => {
	const response = {
		title: "Login",
		error: req.query.error
	}

	res.render('login', response);
});

Task.post('/login', passport.authenticate('local', {
	successRedirect: '/',
	failureRedirect: '/login?error=true'
}));

Task.get('/logout', function (req, res) {
	req.logout();
	res.redirect('/');
});

// Setup the admin user
Task.get('/setup', async (req, res) => {
	const exists = await User.exists({ username: "admin" });

	if (exists) {
        
		res.redirect('/login');
		return;
	};

	bcrypt.genSalt(10, function (err, salt) {
		if (err) return next(err);
		bcrypt.hash("pass", salt, function (err, hash) {
			if (err) return next(err);
			
			const newAdmin = new User({
				username: "admin",
				password: hash
			});

			newAdmin.save();

			res.redirect('/login');
		});
	});
});




Task.listen(3000,()=> {
    console.log("Listening to the port 3000");
});