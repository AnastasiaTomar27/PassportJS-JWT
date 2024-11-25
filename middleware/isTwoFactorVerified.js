// isTwoFactorVerified means that twoFactorSecret = "some secret" and isTwoFactorConfirmed = true
exports.isTwoFactorVerified = async (req, res, next) => {
    if (!req.user.isTwoFactorVerified) {
        return res.status(403).json({
            errors: [{ msg: "Access denied. Please complete Two-Factor Authentication to proceed." }]
        });
    }

    next();
};
