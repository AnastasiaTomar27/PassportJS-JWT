const express = require('express');
const router = express.Router();
const {userRegister, login, setup2FA, reset2FA, verify2FA, userProfile, renewToken, logout, terminateSession, seed, addProductToOrder, checkMyOrder, fetchUserByAdmin, generateInvoice, downloadInvoice, checkInvoice} = require('@controllersUsers');
const {restrict} = require('@middlewareRestrict');
const authenticateJWT = require('@middlewareAuthenticateJWT');

router.post("/signup", userRegister);
router.post('/login', login);
router.post('/setup2FA', authenticateJWT, setup2FA);
router.post('/reset2FA', authenticateJWT, reset2FA);
router.post('/verify2FA', authenticateJWT, verify2FA);
router.get('/profile', authenticateJWT, userProfile);
router.post('/renewAccessToken', renewToken);
router.post('/logout', authenticateJWT, logout);
router.post('/admin/logout-user', authenticateJWT, restrict('1534'), terminateSession);
router.post('/seed', authenticateJWT, restrict('1534'), seed)
router.post('/addProductToOrder', authenticateJWT, addProductToOrder);
router.get('/checkMyOrder', authenticateJWT, checkMyOrder);
router.get('/admin/fetchUser', authenticateJWT, restrict('1534'), fetchUserByAdmin);
router.post('/generate-invoice', authenticateJWT, generateInvoice);
router.get('/downloadInvoice/:filename', downloadInvoice);
router.get('/checkInvoice/:filename', checkInvoice);

module.exports = router;