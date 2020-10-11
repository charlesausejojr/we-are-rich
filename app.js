require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');


const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({ //express-session
  secret: 'This is our secret',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/richDB", {useNewUrlParser: true});
mongoose.set('useNewUrlParser', true);
mongoose.set('useFindAndModify', false);
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String,
    facebookId: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
//**********************************PASSPORT STRATEGIES**********************************//
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
//*******************************************************************************************//
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
//*******************************************************************************************//


app.get("/",function(req,res){
  res.render('home');
});
//**********************************GOOGLE AUTHENTICATION**********************************//
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })); //passport with google strategy

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/poor' }), //passport with google strategy
    function(req, res) {
      res.redirect('/secrets');
});
//*******************************************************************************************//

//**********************************FACEBOOK AUTHENTICATION**********************************//
app.get('/auth/facebook',
  passport.authenticate('facebook', { scope: ['email'] }));

  app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/poor' }),
  function(req, res) {
    res.redirect('/secrets');
  });
//*******************************************************************************************//
app.get("/login",function(req,res){
  res.render('login');
});
app.get("/register",function(req,res){
  res.render('register');
});
app.get("/secrets",function(req,res){
  if(req.isAuthenticated()){ //passport method that checks if user is using this method or not
    res.render("secrets");
  } else{
    res.redirect("/poor");
  }
});
app.get('/logout', function(req, res){
  req.logout();      //passport
  res.redirect('/');
});
app.get('/poor', function(req,res){
  res.render("poor");
});
//**********************************NORMAL REGISTER AND LOGIN**********************************//
app.post("/register",function(req,res){

  User.register({username: req.body.username}, req.body.password, function(err, user){ //local-mongoose
      if(err){
        console.log(err);
        res.redirect('/register');
      } else{
        passport.authenticate("local")(req,res,function(){ //passport
          res.redirect('/secrets');
        });
      }
    });


});

app.post("/login",function(req,res){

  const user = new User({
  username: req.body.username,
  password: req.body.password
});

  req.login(user, function(err){
    if(err){
      res.redirect("/poor");
      console.log(err);
    } else{
      passport.authenticate("local")(req,res,function(){
        res.redirect('/secrets');
      });
    }
  });

});
//*******************************************************************************************//

app.listen(3000,function(){
  console.log("Server Successfully Started");
});
