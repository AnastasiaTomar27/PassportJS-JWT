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
        
        req.user = user;
        next();
    })(req, res, next);
};

module.exports = authenticateJWT;


