require('module-alias/register')
const path = require('path')
require('dotenv').config({path: path.resolve('config/dev.env')})
const express = require("express");
const passport = require('passport')
require('@mongooseConnection')
const { connectDB } = require('@mongooseConnection')
const passportConfig = require('@passport');
const routes = require("@routesUsers");

const app = express();
// Serve static files from the "invoices" directory
// const invoicesDir = path.join(__dirname, 'service/invoices'); 
// app.use('/api/invoices', express.static(invoicesDir));

connectDB()

const PORT = process.env.PORT || 4000; 

app.use(express.json());

app.use(passport.initialize()); //  import and initialize Passport globally so that it's available across all routes

passportConfig(passport);

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

// Express application server (app.listen()) does not start when I'm running tests
if (process.env.NODE_ENV !== 'test') {
    app.listen(PORT, () => console.log("Server is running on port " + PORT));
}

module.exports = app;