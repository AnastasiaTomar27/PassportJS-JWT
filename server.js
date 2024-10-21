require('module-alias/register')
const path = require('path')
require('dotenv').config({path: path.resolve('config/dev.env')})
const express = require("express");
//const session = require('express-session');
const passport = require('passport')
require('@mongooseConnection')
const { connectDB } = require('@mongooseConnection')
const passportConfig = require('@passport');
const routes = require("@routesUsers");
const cookieParser = require('cookie-parser');
const MongoStore = require('connect-mongo');

const secret = process.env.SECRET;
const app = express();

connectDB()

//Define the MongoDB URI based on the environment
// MongoDB connection URI (Uniform Resource Identifier)
const mongoUri = process.env.NODE_ENV === 'test'
  ? 'mongodb://localhost:27017/test' 
  : process.env.MONGODB_URL;

//const PORT = 8002
const PORT = process.env.PORT || 3000; 

// middleware
app.use(express.json());
app.use(cookieParser("jwt learning")); // it makes the cookies easily readable from the request.cookies

app.use(passport.initialize());

passportConfig(passport);

app.get("/", (req, res) => {
    res.send("hello world")
})

// define routes middleware
app.use("/api", routes)

// 404 Error handler - catches undefined routes
app.use((req, res, next) => {
    // 404 - the server could not find a requested resource. 
    res.status(404).json({
        errors: [{
            msg: "Resource not found. The URL you are trying to access does not exist."
        }]
    });
});

app.use((err, req, res, next) => {
    res.status(500).json({
        errors: [{
            msg: "Internal server error. Please try again later."
        }]
    });
});

app.listen(PORT, () => console.log("Server is running on port " + PORT))

module.exports = app;