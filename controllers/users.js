const User = require('@modelsUser');
const passport = require('passport');
const crypto = require('crypto');
const { validationResult, matchedData, body } = require('express-validator');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const keys = process.env.ACCESS_TOKEN_SECRET;
const keys2 = process.env.REFRESH_TOKEN_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD
const accessTokenExpiry = process.env.JWT_ACCESS_TOKEN_EXPIRY // 10min; 
const Order = require('@modelOrder');
const Product = require('@modelProduct');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { buildPDF } = require('@buildPDF');
const path = require('path');
const fs = require('fs');
const invoicesDir = path.join(__dirname, '..', 'service', 'invoices'); // __dirname means the path of users.js, '..' means go from the controllers folder
const { sendInvoiceEmail } = require('@emailService');


exports.userRegister = [
        [
        body("name").notEmpty().isLength({ max: 20 }).withMessage('Name must be maximum of 20 characters.').isString(),
        body("email").notEmpty().isLength({ max: 30 }).withMessage('Email must be maximum of 30 characters.').isString().isEmail(),
        body("password").notEmpty().isLength({ max: 20 }).withMessage('Password must be maximum of 20 characters.').isString()
            .custom(async (value) => {
                const passwordRegex = /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])/;
                if (!passwordRegex.test(value)) {
                    throw new Error(); }
                }).withMessage("User password configuration is invalid"),  
        body("role").optional().isIn(['user', 'admin']).withMessage('Invalid role')
        .custom(async (role, { req }) => {
            // If the user selects 'admin', validate the password
            if (role === 'admin') {
                const { adminPassword } = req.body;
                if (adminPassword !== ADMIN_PASSWORD) {
                    throw new Error('Incorrect admin password.');
                }
            }
            return true;
        }).withMessage('Role selection failed.') 
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
                            data: {
                                name: user.name,
                                email: user.email,
                                userId: user.id,
                                //isMfaActive: false
                            }
                        });                    
                    })
                    .catch((e) => {
                        //console.error("Error while saving user:", e); 

                        if (e.code === 11000) {
                            return response.status(400).send({ errors: [{msg: "User already registered!"}] });
                        } else {
                            return response.status(500).send({ errors: [{msg: "An error occurred while registering the user."}] });
                        }
                    });
            } catch (err) {
                return response.status(500).json({ errors: [{msg: "An error occurred while registering the user."}] });
            }  
        }
]

exports.login = [
    // Validation middlaware
    [
        body("email").notEmpty().isString().isEmail(),
        body("password").notEmpty()
    ],
    // Checking validation results
    async (request, response, next) => {
        const result = validationResult(request);

        if (!result.isEmpty()) {
            return response.status(400).send({ errors: result.array() });
        }
       
        passport.authenticate("local", async (err, user, info) => { // here i only use passport for user validation, but don't attach user to the session 
            
            if (err) {
                return response.status(500).send({ errors: [{ msg: "Internal Server Error" }] });
            }
            
            if (!user) {
                return response.status(401).send({ errors: [{ msg: "Access Denied" }] });
            }

            const randomIdentifier = crypto.randomBytes(16).toString('hex');

            // if (!user.tempAgents) {
            //     user.tempAgents = [];
            // }
            
            const random = randomIdentifier

            user.tempAgents = [{ random: randomIdentifier }];

            user.isTwoFactorVerified = false;

            try {
                await user.save(); // Save the updated agents array to the database
            } catch (saveError) {
                console.error("Error saving user agents:", saveError);
                return response.status(500).send({ errors: [{msg: "Error saving user agents"}] });
            } 

            const payload = { _id: user._id, random };

            let temporaryToken;
            try {
                temporaryToken = jwt.sign(payload, keys, { expiresIn: '5m' });
            } catch (err) {
                return response.status(500).send({ errors: [{msg: "Error generating temporary token"}] });
            }

            const needs2FASetup = !user.twoFactorSecret;

            return response.json({
                msg: needs2FASetup ? "Please set up Two-Factor Authentication." : "TOTP required",
                temporaryToken,  // for TOTP verification
                data: { userId: user._id, needs2FASetup } 
            });

        })(request, response, next);
    }
    
];  

// it saves a 2FA secret for the user (twoFactorSecret) and create QR code
exports.setup2FA = async (req, res) => {
    try {
        const user = req.user;

        if (user.twoFactorSecret) {
            return res.status(400).json({ errors: [{ msg: "2FA is already set up" }] });
        }

        // This secret (secret.base32) is both stored on the server as twoFactorSecret and embedded in a QR code
        var secret = speakeasy.generateSecret();
        user.twoFactorSecret = secret.base32;

        await user.save();
        const url = speakeasy.otpauthURL({ //otpauthURL is a specially formatted URL that encodes the twoFactorSecret along with other information like the user's name and the issuer's name (my website).
            //otpauth://totp/Test%20User?secret=SECRET123&issuer=www.anastasia.com
            secret: secret.base32,
            label: `${user.name}`,
            issuer: "www.anastasia.com",
            encoding: "base32"
        });
        const qrImageUrl = await QRCode.toDataURL(url);
        res.status(200).json({
            QRCode: qrImageUrl
        })
    } catch (error) {
        res.status(500).json({ errors: [{ msg: "Error setting up 2FA" }] });
    }
}

exports.reset2FA = async (req, res) => {
    try {
        const user = req.user;
        
        user.twoFactorSecret = null;
        await user.save();

        // Generate a new 2FA secret and store it
        const secret = speakeasy.generateSecret();
        user.twoFactorSecret = secret.base32;
        await user.save();

        // Generate QR code URL for the new 2FA setup
        const otpauthUrl = speakeasy.otpauthURL({
            secret: secret.base32,
            label: `${user.name}`,
            issuer: "www.anastasia.com",
            encoding: "base32"
        });

        const qrCodeUrl = await QRCode.toDataURL(otpauthUrl);

        // Send QR code back to client for scanning
        res.status(200).json({
            msg: "2FA has been reset successfully",
            QRCode: qrCodeUrl
        });

    } catch (error) {
        console.error("Error resetting 2FA:", error);
        res.status(500).json({ errors: [{ msg: "Error resetting 2FA" }] });
    }
};


exports.verify2FA = async (req, res) => {
    const { totp } = req.body;

    if (!totp) {
        return res.status(422).send({ errors: [{ msg: "TOTP is required" }] });
    }

    const user = req.user;
    if (!user.twoFactorSecret) {
        return res.status(401).send({ message: "TOTP secret not found" });
    }

    const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: "base32",
        token: totp
    });

    if (verified) {
        const sessionRandom = crypto.randomBytes(16).toString('hex');

        if (!user.agents) {
            user.agents = []; // [] means I allow user to log in from different devices
        }
        
        const random = sessionRandom;
        user.agents.push({ random });

        user.isTwoFactorVerified = true;

        try {
            await user.save(); // Save the updated agents array to the database
        } catch (saveError) {
            return res.status(500).send({ errors: [{ msg: "Error saving user agents" }] });
        }

        const payload = { _id: user._id, random};

        let accessToken, refreshToken;
        try {
            accessToken = jwt.sign(payload, keys, { expiresIn: accessTokenExpiry });
            refreshToken = jwt.sign(payload, keys2);
        } catch (err) {
            return res.status(500).send({ errors: [{ msg: "Error generating tokens" }] });
        }

        return res.status(200).json({
            status: true,
            msg: "TOTP validated successfully: user logged in successfully",
            accessToken,
            refreshToken,
            data: {
                user: user.name,
                email: user.email,
                //_id: user._id
            }
        });

    } else {
        res.status(400).json({ message: "TOTP is not correct or expired" });
    }
};

exports.userProfile = async (req, res) => {
    return res.status(200).json({
        data: {
            email: req.user.email,
            name: req.user.name
        }
        
    })
}

exports.renewToken = async (req, res) => {
    try {
        const { refreshToken } = req.body; // Extracting the refresh token from the request body

        if (!refreshToken) {
            // 400 - bad request (request is malformed or incomplete)
            // the server cannot process the request due to client-side issues.
            return res.status(400).json({ errors: [{ msg: "Refresh token is required" }] });
        }

        // Verifying the refresh token
        //decoded -decoded payload (user id, random)
        jwt.verify(refreshToken, keys2, async (err, decoded) => {
            if (err) {
                // 401 -request was not successful because it 
                // lacks valid authentication credentials for the requested resource
                return res.status(401).json({ errors: [{msg: "Invalid or expired refresh token"}] });
            }
            const user = await User.findById(decoded._id);
            if (!user) {
                // 404 - error is about a missing resource
                return res.status(404).json({ errors: [{msg: "User not found"}] });
            }
            const sessionRandom = crypto.randomBytes(16).toString('hex');
            
            user.agents = [];

            const random = sessionRandom
            user.agents.push({
                random
            })
            
            try {
                await user.save(); // Save the updated agents array to the database
            } catch (saveError) {
                return response.status(500).json({ errors: [{msg: "Error saving user agents"}] });
            } 

            const payload = { _id: decoded._id, random: sessionRandom };

            let newAccessToken, newRefreshToken;
            try {
                newAccessToken = jwt.sign(payload, keys, { expiresIn: accessTokenExpiry });
                newRefreshToken = jwt.sign(payload, keys2);
            } catch (err) {
                return response.status(500).json({ errors: [{msg: "Error generating tokens"}] });
            }

            return res.json({
                status: true,
                accessToken: newAccessToken,
                refreshToken: newRefreshToken,
                msg: 'Access token refreshed'
            });
        });

    } catch (error) {
        return res.status(500).json({ errors: [{msg: 'Server error'}] });
    }
};

exports.logout = async (req, res) => {
    try {
        // Assume `req.user` already has the decoded JWT payload with `random` attached
        const currentRandom = req.user.random;

        if (!currentRandom) {
            return res.status(401).json({ errors: [{ msg: "Unauthorized access." }] });
        }

        //console.log("Random identifier before logout:", currentRandom);

        // Filter out the agent associated with the current session, leaving others intact
        req.user.agents = req.user.agents.filter(agent => agent.random !== currentRandom);

        //console.log("Agents array after logout:", req.user.agents);

        // Save the updated user document to reflect the session removal
        await req.user.save();

        return res.status(200).json({ msg: "Logged out successfully" });

    } catch (error) {
        console.error("Error during logout:", error);
        return res.status(500).json({ errors: [{ msg: "Server error" }] });
    }
};


//Admin Route to Terminate User Sessions
exports.terminateSession = async (req,res) => {
    try {
        const { userId } = req.body; 

        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ errors: [{ msg: 'Invalid user ID format' }] });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ errors: [{msg: 'User not found'}] });
        }
    
        //console.log("User agents before:", user.agents);
        // This is if I allow user to log in from one device
        //const random = user.agents.find(agent => agent.random)?.random;
        //user.agents = user.agents.filter(agent => agent.random !== random); // will remove random from agents array

        // this is if I allow user to log in from different devices, so I need to delete all random values from agents, to terminate sessions on different devices
        user.agents = [];
        //console.log("User agents after:", user.agents);

        await user.save(); 

        return res.json({ 
            data: {
                msg: 'User session terminated', 
                userId : user._id, 
                name: user.name,
                email: user.email
            }
            
        });
      } catch (err) {
        console.error("Error during terminateSession:", err);

        return res.status(500).json({ errors: [{msg: 'Error logging out user'}] });
      }
}

// Admin adds products to the store
exports.seed = async (req, res) => {
    try {
        // Predefined products to be seeded
        const products = [
            { name: "Bananas", price: 1.5 },
            { name: "Strawberry", price: 2.5 },
            { name: "Apples", price: 1.5 }
        ];

        // Check if products already exist
        const existingProducts = await Product.find({ name: { $in: products.map(p => p.name) } });

        if (existingProducts.length > 0) {
            return res.status(400).json({ errors: [{ msg: "Some products already exist in the store." }] });
        }

        const newProducts = await Product.create(products);
        return res.status(201).json({
            message: 'Products seeded successfully',
            data: newProducts
        });
    } catch (error) {
        console.error("Error seeding products:", error);
        return res.status(500).json({ errors: [{ msg: "Error seeding products" }] });
    }
}

// user adds products to his order list
exports.addProductToOrder = async (req, res) => {
    if (req.user.isTemporary) {
        return res.status(403).json({ errors: [{ msg: "Temporary token not permitted for this action" }] });
    }
    const { name } = req.body; 

    if (!name) {
        return res.status(400).json({ errors: [{msg: "Product name is required"}] });
    }

    try {
        let order = await Order.findOne({ userId: req.user._id }); // check if user already has order list
        if (!order) {
            order = new Order({ 
                userId: req.user._id,
                products: [] 
            });
        }

        const product = await Product.findOne({ name: name });
        if (!product) {
            return res.status(404).json({ errors: [{msg: "Product not found"}] });
        }

        order.products.push(product._id); // only aads product id

        await order.save();

        // add orders array to the user model
        const user = req.user;
        if (!user.order.includes(order._id)) { // check that order is placed only once
            user.order.push(order._id);
            await user.save();
        }

        await order.populate({ // adds full product details (name, price etc)
            path: 'products'
        });

        const orderDetails = {
            orderId: order._id, 
            createdAt: order.createdAt,
            products: order.products.map(prod => ({
                name: prod.name,
                price: prod.price
            }))
        };

        return res.status(201).json({
            message: 'Product added to order successfully',
            order: orderDetails 
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ errors: [{msg: "Error adding product to order"}] });
    }
};


exports.checkMyOrder = async (req, res) => {
    try {
        const userId = req.user._id; 

        const user = await User.findById(userId)
            .populate({
                path: 'order', 
                populate: {
                    path: 'products', 
                    model: 'Product',
                }
            });

        return res.status(200).json({
            message: 'My order:',
            data: {
                name: user.name,
                email: user.email,
                order: user.order.map(order => ({
                    orderId: order._id,
                    createdAt: order.createdAt,
                    products: order.products.map(product => ({
                        name: product.name,
                        price: product.price,
                    }))
                }))
            }
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ errors: [{msg: "Error checking order"}] });
    }
};

exports.fetchUserByAdmin = async (req, res) => {
    try {
        const userId = req.body.userId;

        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ errors: [{msg: "Invalid user ID format" }] });
        }

        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ errors: [{ msg: 'User not found' }] });
        } 
        
        await user.populate({
                path: 'order',
                populate: {
                    path: 'products',
                    model: 'Product',
                }
            });

        return res.status(200).json({
            data: {
                msg: 'User information and orders:',
                userId: user._id,
                name: user.name,
                email: user.email,
                order: user.order
            }
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ errors: [{msg: 'Error fetching user with orders'}] });
    }
};

exports.generateInvoice = async (req, res) => {
    
    const { orderId } = req.body;

    if (!orderId) {
        return res.status(400).json({ errors: [{ msg: "Order ID is required" }] });
    }

    try {
        const order = await Order.findOne({ _id: orderId, userId: req.user._id })
            .populate('products') 
            .populate({
                path: 'userId',      
                select: 'name email' 
            });

        if (!order) {
            return res.status(404).json({ errors: [{ msg: "Order not found or access denied" }] });
        }

        // buildPDF will pass the path that i created in pdf-service file: resolve(filePath);
        const filePath = await buildPDF(order);
        // generate a publicly accessible URL that clients (e.g., the user’s browser or my frontend application) can use to download or view the file.
        const fileUrl = `/api/invoices/${path.basename(filePath)}`; 

        // Pass the filePath directly to sendInvoiceEmail
        await sendInvoiceEmail(order, order.userId.email, filePath);

        return res.status(200).json({ message: 'Invoice generated and sent successfully', fileUrl });
    } catch (error) {
        console.error('Error generating invoice in catch block:', error.message);

        // If an error occurs in the PDF generation process
        return res.status(500).json({
            errors: [{ message: "Error generating PDF", details: error.message }]
        });
    }
};

// in browser I use ModHeader to put access token and check routes 
exports.invoices = async (req, res) => {
    const { filename } = req.params;
    const download = req.query.download === 'true'; // I need to add ?download=true for downloading: http://localhost:3000/api/invoices/invoice-672fb86119bba8fc4780c8ec.pdf?download=true
    
    try {
        // Define the path to your invoices directory and file location
        const filePath = path.join(invoicesDir, filename);

        // Check if the file exists
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ errors: [{ msg: 'Invoice not found' }] });
        }

        if (download) {
            // Send the file as an attachment (download)
            return res.download(filePath, filename, (err) => {
                if (err) {
                    console.error('File download error:', err);
                    return res.status(500).json({ errors: [{ msg: 'Could not download the file.' }] });
                }
            });
        } else {
            // Send the file inline (to view in the browser)
            res.sendFile(filePath, (err) => {
                if (err) {
                    console.error('File view error:', err);
                    return res.status(500).json({ errors: [{ msg: 'Could not view the file.' }] });
                }
            });
        }
    } catch (error) {
        console.error('Error handling file request:', error);
        return res.status(500).json({ errors: [{ msg: 'Internal server error.' }] });
    }
};








