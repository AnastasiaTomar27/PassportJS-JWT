const express = require('express');
const router = express.Router();
const {userRegister, login, userProfile, renewToken, logout, terminateSession} = require('@controllersUsers');
const passport = require('passport');
//const authenticateToken = require('@middlewareAuthenticateToken');

router.post("/signup", userRegister);
router.post('/login', login);
router.get('/profile', passport.authenticate("jwt", { session: false }), userProfile);
router.post('/renewAccessToken', renewToken);
router.post('/logout', passport.authenticate("jwt", { session: false }), logout);
router.post('/admin/logout-user', terminateSession);


module.exports = router;