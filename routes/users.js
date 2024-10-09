const express = require('express');
const router = express.Router();
const {userRegister, login, userProfile, renewToken, logout} = require('@controllersUsers');
const passport = require('passport')

router.post("/signup", userRegister)
router.post('/login', login)
router.get('/profile', passport.authenticate("jwt", { session: false }), userProfile)
router.post('/renewAccessToken', renewToken)
router.post('/logout', logout);


module.exports = router