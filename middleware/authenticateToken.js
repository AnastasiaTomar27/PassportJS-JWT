// const passport = require('passport');

// const authenticateToken = async (req, res, next) => {
//     const authHeader = req.headers['authorization'];

//     if (!authHeader || !authHeader.startsWith('Bearer ')) {
//         return res.status(401).json({ message: 'Authorization token is required' });
//     }

//     const token = authHeader.split(' ')[1]; // Extract the JWT

//     try {
//         passport.authenticate('jwt', { session: false }, (err, user, info) => {
//             if (err) {
//                 return res.status(500).json({ message: 'Server error during authentication' });
//             }

//             if (!user) {
//                 return res.status(403).json({ message: info ? info.message : 'Token is invalid or expired' });
//             }

//             // If valid, attach user information to request object
//             req.user = user; 
//             next(); 
//         })(req, res); 
//     } catch (err) {
//         console.error('Error during token authentication:', err);
//         return res.status(500).json({ message: 'Server error' });
//     }
// };

// module.exports = authenticateToken;
