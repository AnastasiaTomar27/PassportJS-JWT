const express = require('express');
const router = express.Router();
const {userRegister, login, confirm2FA, manage2FA, verify2FA, userProfile, renewToken, logout, terminateSession, seed, addProductToOrder, checkMyOrder, fetchUserByAdmin, generateInvoice, invoices} = require('@controllersUsers');
const {restrict} = require('@middlewareRestrict');
const authenticateJWT = require('@middlewareAuthenticateJWT');
const { isTwoFactorVerified } = require('../middleware/isTwoFactorVerified');
const { Secret_Confirmed_Verified } = require('../middleware/Secret_Confirmed_Verified'); 
const { temp2FAconfirmed } = require('../middleware/temp2FAconfirmed');

router.post("/signup", userRegister);
router.post('/login', login);
router.post('/manage2FA', authenticateJWT,  Secret_Confirmed_Verified, manage2FA);
router.post('/confirm2FA', authenticateJWT, temp2FAconfirmed, confirm2FA);
router.post('/verify2FA', authenticateJWT, verify2FA);
router.get('/profile', authenticateJWT, isTwoFactorVerified, userProfile);
router.post('/renewAccessToken', renewToken);
router.post('/logout', authenticateJWT, isTwoFactorVerified, logout);
router.post('/admin/logout-user', authenticateJWT, isTwoFactorVerified, restrict('admin'), terminateSession);
router.post('/seed', authenticateJWT, isTwoFactorVerified, restrict('admin'), seed)
router.post('/addProductToOrder', authenticateJWT, isTwoFactorVerified, addProductToOrder);
router.get('/checkMyOrder', authenticateJWT, isTwoFactorVerified, checkMyOrder);
router.get('/admin/fetchUser', authenticateJWT, isTwoFactorVerified, restrict('admin'), fetchUserByAdmin);
router.post('/generate-invoice', authenticateJWT, isTwoFactorVerified, generateInvoice);
router.get('/invoices/:filename', authenticateJWT, isTwoFactorVerified, invoices);

module.exports = router;