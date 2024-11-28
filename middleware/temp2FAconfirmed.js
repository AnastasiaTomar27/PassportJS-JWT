exports.temp2FAconfirmed = async (req, res, next) => {
    if (!req.user.tempTwoFactorSecret) { 
        return res.status(400).json({ errors: [{ msg: "2FA is not set up." }] });
        
    } else {
        next();
    }

};

