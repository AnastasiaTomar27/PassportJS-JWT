require('module-alias/register')
const path = require('path')
require('dotenv').config({path: path.resolve('config/dev.env')})
const express = require("express");
const session = require('express-session');
const passport = require('passport')
require('@mongooseConnection')
const passportConfig = require('@passport');
const routes = require("@routesUsers");
//const MongoStore = require('connect-mongo');


app = express();

//const PORT = 8002
const PORT = process.env.PORT || 3000; 

// middleware
app.use(express.json());
app.use(
    session({
        name: "connect.sid",
        secret: "550b675cf9664e9035f9cd4f2d786bb9647f80b28fca7cc37b6f95b0173d9228d0fcfc00d3b5437f4896eff783c121b72afed4022b9fdd952a6e5a5f3d2eabb3",
        saveUninitialized: false, // false means only when we modife session data ogbect, data will be stored to the session store 
        resave: false, // false means it will not resave cookies every time, expired date wil stay the same
        cookie: {
            maxAge: 60000 * 60 // 60000 mlsec = 60 sec = 1 min, 60000 * 60 = 1 hour
        }
        // store: MongoStore.create({
        //     //client: mongoose.connection.getClient()
        //     mongoUrl:mongoUri
    //})
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

app.listen(PORT, () => console.log("Server is running on port " + PORT))

module.exports = app;