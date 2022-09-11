require('dotenv').config();
const mongoDb = process.env.MONGO_URI;
const express = require('express');
const path = require('path');
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose")
const Schema = mongoose.Schema;

mongoose.connect(mongoDb, {useUnifiedTopology: true, useNewUrlParser: true});
const db = mongoose.connection;
db.on('error', console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
    "User",
    new Schema({
        username: {type: String, required: true},
        password: {type: String, requried: true}
    })
);

const app = express();
//connect to views
app.set("views", __dirname);
app.set("view engine", "ejs");

app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({extended: false}));

//middleware

app.use(function(req, res, next) {
    res.locals.currentUser = req.user;
    next();
  });

//routes
app.get('/', (req, res) => res.render('index', {user: req.user}));

app.get("/sign-up", (req, res) => res.render("sign-up-form"));

//signup controller
app.post("/sign-up", (req, res, next) => {
    const user = new User({
      username: req.body.username,
      password: req.body.password
    }).save(err => {
      if (err) { 
        return next(err);
      }
      res.redirect("/");
    });
  });

  app.post(
    "/log-in",
    passport.authenticate("local", {
      successRedirect: "/",
      failureRedirect: "/"
    })
  );

  app.get("/log-out", (req, res, next) => {
    req.logout(function (err) {
      if (err) {
        return next(err);
      }
      res.redirect("/");
    });
  });

  //setting up the LocalStrategy
  //function acts a bit like a middleware and will be called for us when we ask passport to do the authentication later.
  passport.use(
    new LocalStrategy((username, password, done) => {
      User.findOne({ username: username }, (err, user) => {
        if (err) { 
          return done(err);
        }
        if (!user) {
          return done(null, false, { message: "Incorrect username" });
        }
        if (user.password !== password) {
          return done(null, false, { message: "Incorrect password" });
        }
        return done(null, user);
      });
    })
  );

  //Sessions and serialization
  passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });



app.listen(3000, () => console.log("app listening on port 3000!"))

