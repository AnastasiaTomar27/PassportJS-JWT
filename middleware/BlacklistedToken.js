const passport = require('passport');
const BlacklistedToken = require('../mongoose/models/BlacklistedToken'); // Import BlacklistedToken

const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Authorization token is required' });
    }

    const token = authHeader.split(' ')[1]; // Extract the JWT

    try {
        // Check if the token has been blacklisted
        const blacklisted = await BlacklistedToken.findOne({ token });
        if (blacklisted) {
            return res.status(401).json({ message: 'Token is blacklisted' });
        }

        // Use Passport to authenticate the token
        passport.authenticate('jwt', { session: false }, (err, user, info) => {
            if (err) {
                return res.status(500).json({ message: 'Server error during authentication' });
            }

            if (!user) {
                return res.status(403).json({ message: info ? info.message : 'Token is invalid or expired' });
            }

            // If valid, attach user information to request object
            req.user = user; 
            next(); // Proceed to the next middleware
        })(req, res); // Call the middleware with req and res
    } catch (err) {
        console.error('Error during token authentication:', err);
        return res.status(500).json({ message: 'Server error' });
    }
};

module.exports = authenticateToken;
