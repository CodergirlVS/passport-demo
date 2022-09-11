require('dotenv').config();
const mongoDb = process.env.MONGO_URI;
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true }));