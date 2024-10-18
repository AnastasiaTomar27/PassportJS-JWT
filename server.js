require('module-alias/register')
const path = require('path')
require('dotenv').config({path: path.resolve('config/dev.env')})
const express = require("express");
const session = require('express-session');
const passport = require('passport')
require('@mongooseConnection')
const { connectDB } = require('./mongoose/connection')
const passportConfig = require('@passport');
const routes = require("@routesUsers");
const cookieParser = require('cookie-parser');
const MongoStore = require('connect-mongo');

const secret = process.env.SECRET;
app = express();

connectDB()

//Define the MongoDB URI based on the environment
const mongoUri = process.env.NODE_ENV === 'test'
  ? 'mongodb://localhost:27017/test' 
  : process.env.MONGODB_URL;

//const PORT = 8002
const PORT = process.env.PORT || 3002; 

// middleware
app.use(express.json());
app.use(cookieParser("jwt learning")); // it makes the cookies easily readable from the request.cookies
app.use(
    session({
        name: "connect.sid",
        secret: secret,
        saveUninitialized: false, // false means only when we modife session data ogbect, data will be stored to the session store 
        resave: false, // false means it will not resave cookies every time, expired date wil stay the same
        cookie: {
            maxAge: 60000 * 60 // 60000 mlsec = 60 sec = 1 min, 60000 * 60 = 1 hour
        },
        store: MongoStore.create({
            //client: mongoose.connection.getClient()
            mongoUrl:mongoUri
    })
    })
);
app.use(passport.initialize());
app.use(passport.session()); // attaches dynamic user property to the request object, to know who the user is

passportConfig(passport);

app.get("/", (req, res) => {
    res.send("hello world")
})

// define routes middleware
app.use("/api", routes)

// 404 Error handler - catches undefined routes
app.use((req, res, next) => {
    res.status(404).json({
        errors: [{
            msg: "Resource not found. The URL you are trying to access does not exist."
        }]
    });
});

// Global error handler for 500 - for internal server errors
app.use((err, req, res, next) => {
    console.error("Server error:", err); // Log the error for debugging
    res.status(500).json({
        errors: [{
            msg: "Internal server error. Please try again later."
        }]
    });
});

app.listen(PORT, () => console.log("Server is running on port " + PORT))

module.exports = app;