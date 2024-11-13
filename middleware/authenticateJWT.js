const passport = require('passport');

const authenticateJWT = (req, res, next) => {
    passport.authenticate('jwt', { session: false }, (err, user, info) => {
        if (err) {
            console.error("JWT Authentication Error:", err);
            return res.status(500).json({ errors: [{ msg: "Internal server error" }] });
        }

        if (!user) {
            return res.status(401).json({ errors: [{ msg: "Unauthorized access" }] });
        }

        // console.log("Session type:", user.sessionType);  // 'access' or 'temporary'
        // console.log("Random identifier:", user.random);

        // Handle restrictions based on session type if necessary
        if (user.sessionType === 'temporary') {
            const allowedTemporaryRoutes = ['/setup2FA', '/verify2FA', '/reset2FA'];
            if (!allowedTemporaryRoutes.includes(req.path)) {
                return res.status(403).json({ errors: [{ msg: "Temporary token not permitted for this action" }] });
            }
        }

        req.user = user;
        next();
    })(req, res, next);
};

module.exports = authenticateJWT;


