require("dotenv").config();
const mongoDb = process.env.MONGO_URI;
const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const bcrypt = require("bcryptjs");
const MongoDBStore = require('connect-mongodb-session')(session)
//to store the session data in Mongo db
var store = new MongoDBStore({
  uri: process.env.MONGO_URI,
  collection: 'sessions'
});

// Catch errors
store.on('error', function (error) {
  console.log(error);
});

mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, requried: true },
  })
);

const app = express();
//connect to views
// app.set("views", __dirname);
app.set("view engine", "ejs");

//save the session in mongo
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    store: store,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

//middleware

app.use(function (req, res, next) {
  res.locals.currentUser = req.user;
  next();
});

const authMiddleware = (req, res, next) => {
    if (!req.user) {
      if (!req.session.messages) {
        req.session.messages = []
      }
      req.session.messages.push("You can't access that page before logon.")
      res.redirect('/')
    } else {
      next()
    }
  }

//routes
app.get("/", (req, res) => {
    let messages = [];
    if(req.session.messages){
        messages = req.session.messages
        req.session.messages= [];
    }
    res.render("pages/index", {messages})
});

app.get("/sign-up", (req, res) => res.render("pages/sign-up-form"));

app.get('/restricted', authMiddleware, (req, res) => {
    if (!req.session.pageCount) {
      req.session.pageCount = 1
    } else {
      req.session.pageCount++
    }
    res.render('pages/restricted', { pageCount: req.session.pageCount })
  })

//controller
app.post("/sign-up", async (req, res, next) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await User.create({
      username: req.body.username,
      password: hashedPassword,
    });
    res.redirect("/");
  } catch (err) {
    return next(err);
  }
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
    failureMessage: true
  })
);

app.get("/log-out", (req, res, next) => {
  req.session.destroy(function (err) {
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
      bcrypt.compare(password, user.password, (err, result) => {
        if (result) {
          return done(null, user);
        } else {
          return done(null, false, { message: "Incorrect password" });
        }
      });
    });
  })
);

//Sessions and serialization
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

app.listen(3000, () => console.log("app listening on port 3000!"));
