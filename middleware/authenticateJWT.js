const passport = require('passport');

const authenticateJWT = (req, res, next) => {
    passport.authenticate('jwt', { session: false }, (err, user, info) => {
        if (err) {
            return res.status(500).json({ errors: [{ msg: "Internal server error" }] });
        }

        if (!user) {
            // Authentication failed (e.g., invalid token, user not found, invalid session)
            return res.status(401).json({ errors: [{ msg: "Unauthorized access" }] });
        }

        // Attach the user to the request if authentication succeeds
        req.user = user;
        next();
    })(req, res, next);
};

module.exports = authenticateJWT;
