//jshint esversion:6

require('dotenv').config(); // for env file 

const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption"); // this is level 2 security by unscrabling the username and passwords in the database
// const md5 = require("md5");

// const bcrypt = require("bcrypt");
// const saltRounds = 10;


const session = require("express-session");
const passport = require("passport");
// used passport to add cookies and sessions
const passportLocalMongoose = require("passport-local-mongoose");
const { LEGAL_TCP_SOCKET_OPTIONS } = require('mongodb');
const GoogleStrategy = require("passport-google-oauth20").Strategy; // for google login
const findOrCreate= require("mongoose-findorcreate");


const app = express();

// console.log(process.env.SECRET);

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));

  // set up session using passport.js
app.use(session({
    secret:"Our little secret.",
    resave:false,
    saveUninitialized:false
}));
 // initialize the session 
app.use(passport.initialize());
app.use(passport.session()); 

mongoose.connect(process.env.ATLAS_URL,function(){
    console.log("Connected");
    });
 // user database // mongoose scheama which is secure
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String // user's secret
})

// userSchema.plugin(encrypt, {secret:process.env.SECRET , encryptedFields:["password"]}); // mongooose schema used for encryption

userSchema.plugin(passportLocalMongoose); // used to hash and salt our password and to save our users to mongodb
userSchema.plugin(findOrCreate);
 
// new user
const User = new mongoose.model("User",userSchema)

passport.use(User.createStrategy());

 // serialize the user to cookie stuffs the info of user to the cookie
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
   // seserialize (crumble) the cookie and find the info feed
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID, // present in env file
    clientSecret: process.env.CLIENT_SECRET, // present in env file
    callbackURL: "http://localhost:3008/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user); // find that existing user or create new user by google id
    });
  }
));


app.get("/",function(req,res){
    res.render("home");
});


app.route('/auth/google')
  .get(passport.authenticate('google', {
    scope: ['profile']  // google sign in popup
  }));

app.get("/login",function(req,res){
    res.render("login");
});

app.get("/register",function(req,res){
    res.render("register");
});

app.get("/secrets",function(req,res){
    User.find({"secret":{$ne: null}}, function(err,foundUser){ // get users with secrets ie display user's secrets whose secreat != null
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                res.render("secrets",{usersWithSecrets: foundUser}); // found users with secrets and send this to secret page with ejs
            }
        }
    })
});

app.post("/submit",function(req,res){
    const submittedSecret = req.body.secret; // secret written by user

    // console.log(req.user.id);

    User.findById(req.user.id , function(err,foundUser){
        if(err){
            console.log(err);
        }else{
            foundUser.secret = submittedSecret; // if the user is found then submit user's secret
            foundUser.save(function(){
                res.redirect("/secrets"); // save this newly founded secret of this user and recdirect them to secrets page 
            });
        }
    });
});

app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit")
    }else{
        res.redirect("login");
    }
})

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication with google, redirect secrets.
    res.redirect("/secrets");
  });

app.get("/logout",function(req,res){
    req.logout(function(err){
        if(err){
            console.log(err);
        }  
        else{
            res.redirect("/")
        }
    });        
  // logout and unauthorize the user 
});

app.post("/register", function (req, res) {

    // bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    //     // Store hash in your password DB.
    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash
    //     });
    //     newUser.save(function (err) {
    //         if (!err) {
    //             res.render("secrets");
    //         }
    //         else {
    //             console.log(err);
    //         }
    //     })

    // });

    User.register({username: req.body.username}, req.body.password, function(err,user){
        if(err){
            console.log(err);
            res.redirect("/register");
        } // user regiistering
        else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            }) // registering by creating a passport cookie 
        }
    })


});
// getting new user
app.post("/login",function(req,res){
    // const username = req.body.username;
    // const password = req.body.password;

    // User.findOne({email: username},function(err,foundUser){
    //     if(err){
    //         console.log(err);
    //     }
    //     else{
    //         if(foundUser){
    //             bcrypt.compare(password, foundUser.password, function(err, result) {
    //                 // result == true
    //                 if(result===true){
    //                     res.render("secrets")

    //                 }
                
    //             });
    //         }
    //     }
    // })

    const user=new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user,function(err){
        if(err){
            console.log(err);
        } // if user is not registered or incorect pass throw error
        else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            }); // if user is registered show them secrets page // and logging in by using passport cookie
            
        }
    })


})

app.listen(3008,function(){
    console.log("The server is started in port 3008");
});
