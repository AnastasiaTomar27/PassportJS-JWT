const express = require('express');
const router = express.Router();
const {userRegister, login, userProfile, renewToken, logout, terminateSession} = require('@controllersUsers');
const passport = require('passport');
const authenticateToken = require('@middlewareBlackilistedToken');

router.post("/signup", userRegister);
router.post('/login', login);
router.get('/profile', passport.authenticate("jwt", { session: false }), userProfile);
router.post('/renewAccessToken', renewToken);
router.post('/logout', authenticateToken, logout);
router.post('/admin/logout-user/:userId', authenticateToken, terminateSession);


module.exports = router;