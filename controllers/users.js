const User = require('@modelsUser');
const passport = require('passport');
const crypto = require('crypto');
const BlacklistedToken = require('@modelsBlacklistedToken');
const { validationResult, matchedData, body } = require('express-validator');
const jwt = require('jsonwebtoken');
const RefreshToken = require('@modelsRefreshToken');

const keys = process.env.ACCESS_TOKEN_SECRET;
const keys2 = process.env.REFRESH_TOKEN_SECRET;
const accessTokenExpiry = process.env.JWT_ACCESS_TOKEN_EXPIRY // 10min; 
const refreshTokenExpiry = process.env.JWT_REFRESH_TOKEN_EXPIRY // 30d; 

exports.userRegister = [
        [
        body("name").notEmpty().isLength({ max: 20 }).withMessage('Name must be maximum of 20 characters.').isString(),
        body("email").notEmpty().isLength({ max: 30 }).withMessage('Email must be maximum of 30 characters.').isString(),
        body("password").notEmpty().isLength({ max: 20 }).withMessage('Password must be maximum of 20 characters.').isString()
            .custom(async (value) => {
                const passwordRegex = /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])/;
                if (!passwordRegex.test(value)) {
                    throw new Error(); }
                }).withMessage("User password configuration is invalid")  
        ],
        async (request, response) => {
            const result = validationResult(request);
    
            if (!result.isEmpty()) {
                return response.status(400).send({ errors: result.array() });
            }     
    
            const data = matchedData(request);
            const newUser = new User(data);

            try {
                await newUser.save()
                    .then((user) => {
                        return response.status(201).json({
                            success: true,
                            msg: "User created",
                            //data: userWithoutPassword
                            data: {
                                userId: user.id
                            }
                        });                    
                    })
                    .catch((e) => {
                        console.error("Error while saving user:", e); 

                        if (e.code === 11000) {
                            return response.status(400).json({ message: "User already registered!" });
                        } 
                    });
            } catch (err) {
                console.log(err);
                return response.status(500).json({ message: "An error occurred while registering the user." });
            }
        }
]


exports.login = [
    // Validation middlaware
    [
        body("email").notEmpty().isLength({ max: 20 }).withMessage('Email must be maximum of 20 characters.').isString(),
        body("password").notEmpty().isLength({ max: 30 }).withMessage('Password must be maximum of 30 characters.').isString()
        .custom(async (value) => {
            const passwordRegex = /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])/;
            if (!passwordRegex.test(value)) {
                throw new Error(); }
            }).withMessage("User password configuration is invalid")
    ],
    // Checking validation results
    async (request, response, next) => {
        const result = validationResult(request);

        if (!result.isEmpty()) {
            return response.status(400).send({ errors: result.array() });
        }
       
        // Proceed with Passport.js authentication
        passport.authenticate("local", async (err, user, info) => { // here i only use passport for userauthentication, but don't attach user to the session 
            if (!user) {
                return response.status(401).send({ message:  "Access Denied"});
            }

            //JWT session management system where an administrator can log out users by invalidating their JWT tokens.
            // Generate a random session identifier
           
            const sessionRandom = crypto.randomBytes(16).toString('hex');
            // Initialize agents array if it's undefined.  The code checks if agents exists
            if (!user.agents) {
                user.agents = [];
            }
            
            user.agents.push({
                random: sessionRandom
            })

            try {
                await user.save(); // Save the updated agents array to the database
            } catch (saveError) {
                console.error("Error saving user agents:", saveError);
                return response.status(500).json({ msg: "Error saving user agents" });
            } 

            const payload = { _id: user._id, random: sessionRandom };

            // // Generate JWT tokens
            let accessToken, refreshToken;
            try {
                accessToken = jwt.sign(payload, keys, { expiresIn: accessTokenExpiry });
                refreshToken = jwt.sign(payload, keys2, { expiresIn: refreshTokenExpiry });
            } catch (err) {
                console.error("Error generating tokens:", err);
                return response.status(500).json({ msg: "Error generating tokens" });
            }

            // Remove any existing refresh tokens for the same session before saving the new one
            await RefreshToken.deleteMany({ user: user._id, session: sessionRandom });

            // Store refresh token in the database
            try {
                const newRefreshToken = new RefreshToken({
                    token: refreshToken,
                    user: user._id,
                    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days expiration
                });

                await newRefreshToken.save();
                const { password, ...userWithoutPassword } = user.toObject();

                return response.json({
                    status: true,
                    msg: "Logged in successfully",
                    accessToken: accessToken,
                    refreshToken: refreshToken,
                    user: userWithoutPassword // This will omit the password from the response

                });
            } catch (error) {
                console.log("Error in saving refresh token:", error);
                return response.status(500).json({ msg: "Server error" });
            }
        
        })(request, response, next);
    }
    
];  

// exports.login = [
//     // Validation middlaware
//     [
//         body("email").notEmpty().isLength({ max: 20 }).withMessage('Email must be maximum of 20 characters.').isString(),
//         body("password").notEmpty().isLength({ max: 30 }).withMessage('Password must be maximum of 30 characters.').isString()
//         .custom(async (value) => {
//             const passwordRegex = /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])/;
//             if (!passwordRegex.test(value)) {
//                 throw new Error(); }
//             }).withMessage("User password configuration is invalid")
//     ],
//     // Checking validation results
//     async (request, response, next) => {
//         const result = validationResult(request);

//         if (!result.isEmpty()) {
//             return response.status(400).send({ errors: result.array() });
//         }
       
//         // Proceed with Passport.js authentication
//         passport.authenticate("local", async (err, user, info) => { // here i only use passport for userauthentication, but don't attach user to the session 
//             if (!user) {
//                 return response.status(401).send({ message:  "Access Denied"});
//             }

            
//         })(request, response, next);
//     }
    
// ];  



exports.userProfile = async (req, res) => {
    const userProfile = await User.findById(req.user._id);
    return res.json({
        email: userProfile.email,
        name: userProfile.name
    })
}

exports.renewToken = async (req, res) => {
    try {
        const { refreshToken } = req.body; // Extracting the refresh token from the request body

        if (!refreshToken) {
            return res.status(401).json({ msg: "Refresh token is required" });
        }

        // Checking if the refresh token exists in the database
        const storedRefreshToken = await RefreshToken.findOne({ token: refreshToken });
        if (!storedRefreshToken) {
            return res.status(403).json({ msg: "Invalid refresh token" });
        }

        // Verifying the refresh token
        jwt.verify(refreshToken, keys2, async (err, decoded) => {
            if (err) {
                console.log("JWT verification error:", err)
                return res.status(403).json({ msg: "Unauthorized: Invalid or expired refresh token" });
            }

            // Refresh token is valid, generating a new access token
            const newAccessToken = jwt.sign({ _id: decoded._id, email: decoded.email }, keys, { expiresIn: '1m' });

            // generating a new refresh token 
            const newRefreshToken = jwt.sign({ _id: decoded._id, email: decoded.email }, keys2, { expiresIn: '30d' });

            // Updating the refresh token in the database
            await RefreshToken.findOneAndUpdate({ user: decoded._id }, { token: newRefreshToken });

            // Returning the new tokens
            return res.json({
                status: true,
                accessToken: newAccessToken,
                refreshToken: newRefreshToken,
                msg: 'Access token refreshed',
            });
        });

    } catch (error) {
        console.log('Error refreshing access token', error);
        return res.status(500).json({ msg: 'Server error' });
    }
};

exports.logout = async (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(401).json({ msg: "Refresh token is required" });
        }

        // Finding the refresh token in the database and removing it
        const deletedToken = await RefreshToken.findOneAndDelete({ token: refreshToken });

        if (!deletedToken) {
            return res.status(400).json({ msg: "Invalid refresh token" });
        }

        return res.json({ msg: "Logged out successfully" });

    } catch (error) {
        console.log("Error logging out", error);
        return res.status(500).json({ msg: "Server error" });
    }
};

//Admin Route to Terminate User Sessions
exports.terminateSession = async (req,res) => {
    try {
        const userId = req.params.userId;
        const { random } = req.body; // The random value to remove from agents array

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
    
        // Remove the session from the agents array
        user.agents = user.agents.filter(agent => agent.random !== random); // will remove random from agents array

        // Remove refresh tokens associated with this session
        await RefreshToken.deleteMany({ user: userId, session: random }); // Remove tokens tied to this session

        await user.save(); // saving to database without random in agents

        // Check for the Bearer token
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ message: 'Authorization token is required' });
        }

        const tokenToBlacklist = authHeader.split(' ')[1]; // Extract the token
        
        // Check if the token is already blacklisted
        const isBlacklisted = await BlacklistedToken.findOne({ token: tokenToBlacklist });
        if (!isBlacklisted) {
            await BlacklistedToken.create({ token: tokenToBlacklist }); // Save to blacklist
            console.log("Token blacklisted successfully:", tokenToBlacklist);
            // Log all blacklisted tokens for debugging
            const allBlacklistedTokens = await BlacklistedToken.find({});
            console.log("Current blacklisted tokens:", allBlacklistedTokens);
        }

        return res.json({ 
            message: 'User session terminated', 
            userId : user._id, 
            agentsEmpty: user.agents.length === 0});
      } catch (err) {
        console.error('Error terminating session:', err);
        return res.status(500).json({ message: 'Error logging out user' });
      }
}





