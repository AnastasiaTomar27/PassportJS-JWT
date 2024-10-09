require('module-alias/register')
const path = require('path')
require('dotenv').config({path: path.resolve('config/dev.env')})
const express = require("express");
const passport = require('passport')
require('@mongooseConnection')
const passportConfig = require('@passport');
const routes = require("@routesUsers");


app = express();

//const PORT = 8002
const PORT = process.env.PORT || 3000; 

// middleware
app.use(express.json());
app.use(passport.initialize());
passportConfig(passport);

app.get("/", (req, res) => {
    res.send("hello world")
})

// define routes middleware
app.use("/api", routes)

app.listen(PORT, () => console.log("Server is running on port " + PORT))

module.exports = app;