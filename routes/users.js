const express = require('express');
const router = express.Router();
const {userRegister, login, userProfile, renewToken, logout, terminateSession} = require('@controllersUsers');
const passport = require('passport');
const {restrict} = require('../middleware/restrict');
router.post("/signup", userRegister);
router.post('/login', login);

router.get('/profile', (req, res, next) => {
    passport.authenticate('jwt', { session: false }, (err, user, info) => {
        if (err) {
            return res.status(500).json({ errors: [{msg: "Internal server error"}] });
        }
        
        if (!user) {
            // Authentication failed (e.g. invalid token, user not found, invalid session)
            return res.status(401).json({ errors: [{msg: "Unauthorized access"}] });
        }

        // Attach the user to the request if authentication succeeds
        req.user = user;
        next();
    })(req, res, next);
}, userProfile);

router.post('/renewAccessToken', renewToken);

router.post('/logout', (req, res, next) => {
    passport.authenticate('jwt', { session: false }, (err, user, info) => {
        if (err) {
            return res.status(500).json({ errors: [{msg: "Internal server error"}] });
        }
        
        if (!user) {
            // Authentication failed (e.g. invalid token, user not found, invalid session)
            return res.status(401).json({ errors: [{msg: "Unauthorized access"}] });
        }

        // Attach the user to the request if authentication succeeds
        req.user = user;
        next();
    })(req, res, next);
}, logout);

router.post('/admin/logout-user', (req, res, next) => {
    passport.authenticate('jwt', { session: false }, (err, user, info) => {
        if (err) {
            return res.status(500).json({ errors: [{msg: "Internal server error"}] });
        }
        
        if (!user) {
            // Authentication failed (e.g. invalid token, user not found, invalid session)
            return res.status(401).json({ errors: [{msg: "Unauthorized access"}] });
        }

        // Attach the user to the request if authentication succeeds
        req.user = user;
        next();
    })(req, res, next);
}, restrict('1534'), terminateSession);


module.exports = router;