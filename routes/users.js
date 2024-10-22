const express = require('express');
const router = express.Router();
const {userRegister, login, userProfile, renewToken, logout, terminateSession} = require('@controllersUsers');
const {restrict} = require('@middlewareRestrict');
const authenticateJWT = require('@middlewareAuthenticateJWT');


router.post("/signup", userRegister);

router.post('/login', login);

router.get('/profile', authenticateJWT, userProfile);

router.post('/renewAccessToken', renewToken);

router.post('/logout', authenticateJWT, logout);

router.post('/admin/logout-user', authenticateJWT, restrict('1534'), terminateSession);


module.exports = router;