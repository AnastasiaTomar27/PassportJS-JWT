const express = require('express');
const router = express.Router();
const {userRegister, login, userProfile, renewToken, logout, terminateSession, fetchUser, addProduct, fetchUserByAdmin} = require('@controllersUsers');
const {restrict} = require('@middlewareRestrict');
const authenticateJWT = require('@middlewareAuthenticateJWT');

router.post("/signup", userRegister);

router.post('/login', login);

router.get('/profile', authenticateJWT, userProfile);

router.post('/renewAccessToken', renewToken);

router.post('/logout', authenticateJWT, logout);

router.post('/admin/logout-user', authenticateJWT, restrict('1534'), terminateSession);

router.get('/fetchUser', authenticateJWT, fetchUser);

router.get('/admin/fetchUser', authenticateJWT, restrict('1534'), fetchUserByAdmin);

router.post('/addProduct', authenticateJWT, addProduct);

//router.post('/createOrder', authenticateJWT, createOrder);

module.exports = router;