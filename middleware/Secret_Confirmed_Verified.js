const { isTwoFactorVerified } = require('./isTwoFactorVerified');


exports.Secret_Confirmed_Verified = async (req, res, next) => {
    if (req.user.twoFactorSecret && req.user.isTwoFactorConfirmed) { 
        isTwoFactorVerified(req, res, next)
    } else {
        next();
    }

};


