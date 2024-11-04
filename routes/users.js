const express = require('express');
const router = express.Router();
const {userRegister, login, userProfile, renewToken, logout, terminateSession, addProductToTheShop, addProductToOrder, checkMyOrder, fetchUserByAdmin} = require('@controllersUsers');
const {restrict} = require('@middlewareRestrict');
const authenticateJWT = require('@middlewareAuthenticateJWT');

router.post("/signup", userRegister);

router.post('/login', login);

router.get('/profile', authenticateJWT, userProfile);

router.post('/renewAccessToken', renewToken);

router.post('/logout', authenticateJWT, logout);

router.post('/admin/logout-user', authenticateJWT, restrict('1534'), terminateSession);

router.post('/addProductToTheShop', authenticateJWT, restrict('1534'), addProductToTheShop);

router.post('/addProductToOrder', authenticateJWT, addProductToOrder);

router.get('/checkMyOrder', authenticateJWT, checkMyOrder);

router.get('/admin/fetchUser', authenticateJWT, restrict('1534'), fetchUserByAdmin);



module.exports = router;