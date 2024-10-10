const User = require('@modelsUser');
const passport = require('passport');

//const passport = require('../config/passport');
//require('../config/passport')(passport);

const { validationResult, matchedData, body } = require('express-validator');
//const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const RefreshToken = require('../mongoose/models/RefreshToken');

const keys = process.env.ACCESS_TOKEN_SECRET;
const keys2 = process.env.REFRESH_TOKEN_SECRET;

exports.userRegister = [
        [
        body("name").notEmpty().isLength({ max: 20 }).withMessage('Name must be maximum of 20 characters.').isString(),
        body("email").notEmpty().isLength({ max: 20 }).withMessage('Email must be maximum of 20 characters.').isString(),
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
                const userAvailable = await User.findOne({email: data.email});
                if (userAvailable) {
                    return response.status(400).json({message: "User already registered!"});
                }
                const savedUser = await newUser.save();

                // Omit the password before sending the response
                const { password, ...userWithoutPassword } = savedUser.toObject();

                return response.status(201).json({
                    success: true,
                    msg: "User created",
                    data: userWithoutPassword
                });
            } catch (err) {
                console.log(err);
                return response.status(400);
            }
        }
]


exports.login = [
    // Validation middlaware
    [
        body("email").notEmpty().isLength({ max: 20 }).withMessage('Email must be maximum of 20 characters.').isString(),
        body("password").notEmpty().isLength({ max: 20 }).withMessage('Password must be maximum of 20 characters.').isString()
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
       
        //const data = matchedData(request);

        // Proceed with Passport.js authentication
        // Proceed with Passport.js authentication
        passport.authenticate("local", async (err, user, info) => {
            if (err) {
                return response.status(500).json({ err });
            }
            if (!user) {
                return response.status(401).json({ message: "Access denied" });
            }

            request.logIn(user, async (err) => {
                if (err) {
                    return response.status(500).json({ message: "Login failed" });
                }

                // Generate JWT tokens
                const payload = { _id: user._id, email: user.email };
                let accessToken, refreshToken;
                try {
                    accessToken = jwt.sign(payload, keys, { expiresIn: '1m' });
                    refreshToken = jwt.sign(payload, keys2, { expiresIn: '30d' });
                } catch (err) {
                    console.error("Error generating tokens:", err);
                    return response.status(500).json({ msg: "Error generating tokens" });
                }

                // Store refresh token in the database
                try {
                    const newRefreshToken = new RefreshToken({
                        token: refreshToken,
                        user: user._id,
                        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days expiration
                    });

                    await newRefreshToken.save();

                    return response.json({
                        status: true,
                        msg: "Logged in successfully",
                        accessToken: accessToken,
                        refreshToken: refreshToken
                    });
                } catch (error) {
                    console.log("Error in saving refresh token:", error);
                    return response.status(500).json({ msg: "Server error" });
                }
            });
        })(request, response, next);
    }
    
]  


// I use passport.js here
exports.userProfile = async (req, res) => {
    console.log(req.user);
    // const userProfile = await User.findById(req.user._id).select('-password');
    // return res.json(userProfile)
    return res.json(req.user)
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

            // Optionally, generating a new refresh token 
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
            return res.status(400).json({ msg: "Refresh token is required" });
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


