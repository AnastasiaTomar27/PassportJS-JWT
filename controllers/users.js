const User = require('@modelUser');
const passport = require('passport');
const crypto = require('crypto');
const { validationResult, matchedData, body } = require('express-validator');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const keys = process.env.ACCESS_TOKEN_SECRET;
const keys2 = process.env.REFRESH_TOKEN_SECRET;
const accessTokenExpiry = process.env.JWT_ACCESS_TOKEN_EXPIRY // 5min; 
const Order = require('@modelOrder');
const Product = require('@modelProduct');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { buildPDFfromHTML  } = require('@buildPDFfromHTML');
const path = require('path');
const fs = require('fs');
const invoicesDir = path.join(__dirname, '..', 'service', 'invoices'); // __dirname means the path of users.js, '..' means go from the controllers folder
const { sendInvoiceEmail, sendEmailToAdmin } = require('@emailService');
const { isTwoFactorVerified } = require('../middleware/isTwoFactorVerified');
const Invoice = require('../mongoose/models/invoice');

// Helper function
const generateTokens = (user, random) => {
    const payload = { _id: user._id, random };
    const accessToken = jwt.sign(payload, keys, { expiresIn: accessTokenExpiry });
    const refreshToken = jwt.sign(payload, keys2);
    return { accessToken, refreshToken };
};

exports.userRegister = [
    [
    body("name").notEmpty().isLength({ max: 20 }).withMessage('Name must be maximum of 20 characters.').isString(),
    body("email").notEmpty().isLength({ max: 30 }).withMessage('Email must be maximum of 30 characters.').isString().isEmail(),
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
        const newUser = new User({
            name: data.name,
            email: data.email,
            password: data.password
        });

        await newUser.save()
            .then((user) => {
                return response.status(201).json({
                    success: true,
                    msg: "User created",
                    data: {
                        name: user.name,
                        email: user.email
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
    }
]

exports.login = [
    // Validation middlaware
    [
        body("email").notEmpty().isString().isEmail(),
        body("password").notEmpty().isString()
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

            if (user.isLocked) {
                return response.status(403).send({ errors: [{ msg: "Account is locked due to too many failed TOTP attempts." }] });
            }

            // // Attach user to request for isLocked middleware
            // request.user = user;
        
            const random = crypto.randomBytes(16).toString('hex');
            user.agents.push({ random }); // Allow login from different devices
            user.isTwoFactorVerified = false;
    
            try {
                await user.save();
            } catch (saveError) {
                return response.status(500).send({ errors: [{ msg: "Internal Server Error" }] });
            }
    
            const payload = { _id: user._id, random };
    
            let accessToken;
            try {
                accessToken = jwt.sign(payload, keys, { expiresIn: accessTokenExpiry });
            } catch (err) {
                console.error(err);
                return response.status(500).send({ errors: [{ msg: "Internal Server Error" }] });
            }
    
            const needs2FASetup = !user.twoFactorSecret;
    
            return response.json({
                msg: needs2FASetup ? "Please set up Two-Factor Authentication." : "TOTP required",
                data: { userId: user._id, needs2FASetup, accessToken: accessToken },
            });
        })(request, response, next);
    }
];  

exports.manage2FA = async (req, res) => {
    const { totp } = req.body; // Current TOTP code for resetting 2FA if already set up

    try {
        const user = req.user;
        let secret; // Declare secret in the outer scope

        // Check if the user already has a TOTP setup
        if (user.twoFactorSecret && user.isTwoFactorConfirmed) { // Only users with confirmed 2FA can reset
            // Verify the current TOTP to allow the reset
            if (!totp) {
                return res.status(422).json({ errors: [{ msg: "Current TOTP is required to reset 2FA." }] });
            }

            // Verify the current TOTP with the existing secret
            const isVerified = speakeasy.totp.verify({
                secret: user.twoFactorSecret,
                encoding: "base32",
                token: totp,
            });

            if (!isVerified) {
                return res.status(400).json({ errors: [{ msg: "Invalid or expired TOTP code." }] });
            }

            // Clear old TOTP configurations
            user.failedTOTPAttempts = 0;
            // Generate a new TOTP secret directly
            secret = speakeasy.generateSecret();
            user.tempTwoFactorSecret = secret.base32; // only temp secret
            user.twoFactorSecret = ""
            user.isTwoFactorVerified = false; 
            user.isTwoFactorConfirmed = false;
        } else {
            // Generate a new TOTP secret directly
            secret = speakeasy.generateSecret();
            user.twoFactorSecret = secret.base32; // Replace the old secret
        }

        await user.save();

        // Generate a QR code for the new secret
        const otpauthUrl = speakeasy.otpauthURL({
            secret: secret.base32,
            label: `${user.name}`,
            issuer: "www.anastasia.com",
            encoding: "base32",
        });

        const qrCodeUrl = await QRCode.toDataURL(otpauthUrl);
        const message = user.tempTwoFactorSecret ? 
            "Please scan the QR code in your authenticator app and confirm the TOTP code.":
            "Please scan the QR code in your authenticator app to set it up and after that confirm it.";
        
            return res.status(200).json({
            msg: message,
            QRCode: qrCodeUrl,
        });
    } catch (error) {
        console.error("Error managing 2FA:", error);
        res.status(500).json({ errors: [{ msg: "Error managing 2FA." }] });
    }
};

exports.confirm2FA = async (req, res) => {
    const { totp } = req.body;
    const user = req.user;

    if (!totp) {
        return res.status(422).json({ errors: [{ msg: "TOTP is required to confirm 2FA setup." }] });
    }

    if (user.isTwoFactorConfirmed) {
        return res.status(400).json({ errors: [{ msg: "TOTP setup is already confirmed." }] });
    }

    try {
        if (user.tempTwoFactorSecret) {
            const isVerified = speakeasy.totp.verify({
                secret: user.tempTwoFactorSecret,
                encoding: "base32",
                token: totp,
            });

            if (!isVerified) {
                return res.status(400).json({ errors: [{ msg: "Invalid or expired TOTP code." }] });
            }

            const permanentSecret = speakeasy.generateSecret();
            user.twoFactorSecret = permanentSecret.base32;
            user.tempTwoFactorSecret = "";
            user.isTwoFactorConfirmed = true;
            user.failedTOTPAttempts = 0;

            try {
                await user.save();
            } catch (saveError) {
                console.error("Error saving user during TOTP confirmation:", saveError);
                return res.status(500).send({ errors: [{ msg: "Internal Server Error" }] });
            }

            const qrCodeUrl = await generateQRCode(permanentSecret, user);

            return res.status(200).json({
                msg: "Please scan again the QR code in your authenticator app to complete TOTP reset and verify the TOTP code.",
                QRCode: qrCodeUrl,
            });
        } else if (user.twoFactorSecret) {
            const isVerified = speakeasy.totp.verify({
                secret: user.twoFactorSecret,
                encoding: "base32",
                token: totp,
            });

            if (!isVerified) {
                return res.status(400).json({ errors: [{ msg: "Invalid or expired TOTP code." }] });
            }

            user.isTwoFactorConfirmed = true;

            try {
                await user.save();
            } catch (saveError) {
                console.error("Error saving user during TOTP confirmation:", saveError);
                return res.status(500).send({ errors: [{ msg: "Internal Server Error" }] });
            }

            return res.status(200).json({
                msg: "TOTP has been successfully confirmed.",
            });
        } else {
            return res.status(400).json({ errors: [{ msg: "2FA is not set up." }] });
        }
    } catch (error) {
        console.error("Error confirming TOTP:", error);
        return res.status(500).send({ errors: [{ msg: "Internal Server Error" }] });
    }
};

exports.verify2FA = async (req, res) => {
    const { totp } = req.body;

    if (!totp) {
        return res.status(422).send({ errors: [{ msg: "TOTP is required" }] });
    }
    const user = req.user;

    if (user.isLocked) {
        return res.status(403).json({
            errors: [{ msg: "Account is locked due to too many failed TOTP attempts." }],
        });
    }

    if (user.isTwoFactorVerified) {
        return res.status(400).json({
            errors: [{ msg: "You have already verified your 2FA." }]
        });
    }

    if (!user.isTwoFactorConfirmed) {
        return res.status(400).json({
            errors: [{ msg: "You have not confirmed your 2FA setup yet. Please complete the setup." }]
        });
    }

    try {
        const isVerified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: "base32",
            token: totp,
        });

        if (!isVerified) {
            user.failedTOTPAttempts += 1;

            if (user.failedTOTPAttempts >= 10 && !user.isLocked) {
                user.agents = []; // Clear all session identifiers
                user.isLocked = true;

                try {
                    await user.save();
                } catch (saveError) {
                    console.error("Error saving user during account lock:", saveError);
                    return res.status(500).send({ errors: [{ msg: "Internal Server Error" }] });
                }

                await sendEmailToAdmin({
                    subject: "Account Locked",
                    text: `The account associated with email ${user.email} has been locked due to multiple failed TOTP attempts.`,
                });

                return res.status(403).json({
                    errors: [{ msg: "Account is locked due to too many failed TOTP attempts." }],
                });
            }

            try {
                await user.save();
            } catch (saveError) {
                console.error("Error saving user during failed TOTP attempt:", saveError);
                return res.status(500).send({ errors: [{ msg: "Internal Server Error" }] });
            }

            return res.status(400).json({ errors: [{ msg: "Invalid or expired TOTP code" }] });
        }

        user.failedTOTPAttempts = 0;
        user.isLocked = false;
        user.isTwoFactorVerified = true;

        // Clean up old agents and add a new one
        user.agents = user.agents.filter(agent => agent.random !== req.random);
        const random = crypto.randomBytes(16).toString('hex');
        user.agents.push({ random });

        try {
            await user.save();
        } catch (saveError) {
            console.error("Error saving user during TOTP verification:", saveError);
            return res.status(500).send({ errors: [{ msg: "Internal Server Error" }] });
        }

        const { accessToken, refreshToken } = generateTokens(user, random);

        return res.status(200).json({
            status: true,
            msg: "TOTP verified successfully",
            accessToken,
            refreshToken,
            data: {
                user: user.name,
                email: user.email,
            },
        });
    } catch (error) {
        console.error("Error verifying TOTP:", error);
        return res.status(500).send({ errors: [{ msg: "Internal Server Error" }] });
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
        const { refreshToken } = req.body;

        if (!refreshToken) {
            // 400 - bad request (request is malformed or incomplete)
            // the server cannot process the request due to client-side issues.
            return res.status(400).json({ errors: [{ msg: "Refresh token is required" }] });
        }

        // Verifying the refresh token
        //decoded -decoded payload (user id, random)
        jwt.verify(refreshToken, keys2, async (err, decoded) => {
            if (err) {
                // 401 -request was not successful because it lacks valid authentication credentials for the requested resource
                return res.status(401).json({ errors: [{msg: "Invalid or expired refresh token"}] });
            }

            const user = await User.findById(decoded._id);
            if (!user) {
                // 404 - error is about a missing resource
                return res.status(404).json({ errors: [{msg: "User not found"}] });
            }

            // Manually attach user to req
            req.user = user;

            // Check if the user has completed two-factor authentication
            isTwoFactorVerified(req, res, async (middlewareError) => {
                if (middlewareError) {
                    // When called with an argument, e.g., next(middlewareError), Express interprets the argument as an error. It skips all remaining middleware and route handlers and invokes any error-handling middleware (defined with app.use((err, req, res, next) => {...})).
                    return next(middlewareError); // it will send email alert to the admin and will show error:  "Access denied. Please complete Two-Factor Authentication to proceed."
                }

                // Proceed with token renewal
                const sessionRandom = crypto.randomBytes(16).toString('hex');
                const random = sessionRandom;
                user.agents.push({ random });

                try {
                    user.agents = user.agents.filter(agent => agent.random !== decoded.random);
                    await user.save();
                } catch (saveError) {
                    return res.status(500).json({ errors: [{ msg: "Error saving user agents" }] });
                }

                const payload = { _id: decoded._id, random: sessionRandom };

                let newAccessToken, newRefreshToken;
                try {
                    newAccessToken = jwt.sign(payload, keys, { expiresIn: accessTokenExpiry });
                    newRefreshToken = jwt.sign(payload, keys2);
                } catch (tokenError) {
                    return res.status(500).json({ errors: [{ msg: "Error generating tokens" }] });
                }

                return res.json({
                    status: true,
                    accessToken: newAccessToken,
                    refreshToken: newRefreshToken,
                    msg: 'Access token refreshed',
                });
            });
        });

    } catch (error) {
        return res.status(500).json({ errors: [{msg: 'Server error'}] });
    }
};

exports.logout = async (req, res) => {
    try {
        const currentRandom = req.random; 

        if (!currentRandom) {
            return res.status(401).json({ errors: [{ msg: "Unauthorized access." }] });
        }

        // only current random value will be deleted, user can access routes on other devices with other random values in jwt
        req.user.agents = req.user.agents.filter(agent => agent.random !== currentRandom);

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
            
        // admin deletes all random values from agents, to terminate all sessions from all devices
        user.agents = [];

        // should i also to do this?:
        // isTwoFactorConfirmed = false;
        // isTwoFactorVerified = false;
        // twoFactorSecret = "";
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
        //console.error("Error during terminateSession:", err);

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

        // Format the response data to exclude __v
        const formattedProducts = newProducts.map(product => ({
            productId: product._id,
            name: product.name,
            price: product.price,
            createdAt: product.createdAt,
        }));
        
        return res.status(201).json({
            message: 'Products seeded successfully',
            data: formattedProducts
        });
    } catch (error) {
        console.error("Error seeding products:", error);
        return res.status(500).json({ errors: [{ msg: "Error seeding products" }] });
    }
}

// user adds products to his order list
exports.addProductToOrder = async (req, res) => {
    const { productId  } = req.body; 

    if (!productId ) {
        return res.status(400).json({ errors: [{msg: "Product ID is required"}] });
    }

    try {
        const product = await Product.findById(productId);
        if (!product) {
            return res.status(404).json({ errors: [{msg: "Product not found"}] });
        }

        let order = await Order.findOne({ userId: req.user._id }); // check if user already has order list
        if (!order) {
            order = new Order({ 
                userId: req.user._id,
                products: [] 
            });
        }

        order.products.push(product._id); // only aads product id

        await order.save();

        // add orders array to the user model
        const user = req.user;
        if (!user.orders.includes(order._id)) { // check that order is placed only once
            user.orders.push(order._id);
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
        //console.error(error);
        return res.status(500).json({ errors: [{msg: "Error adding product to order"}] });
    }
};


exports.checkMyOrder = async (req, res) => {
    try {
        const userId = req.user._id; 

        const user = await User.findById(userId)
            .populate({
                path: 'orders', 
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
                order: user.orders.map(order => ({
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
        //console.error(error);
        return res.status(500).json({ errors: [{msg: "Error checking order"}] });
    }
};

exports.fetchUserByAdmin = async (req, res) => {
    try {
        const userId = req.body.userId;

        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ errors: [{msg: "Invalid user ID format" }] });
        }

        const user = await User.findById(userId)
            .populate({
                path: 'orders',
                populate: {
                    path: 'products',
                    model: 'Product',
                }
            });

        if (!user) {
            return res.status(404).json({ errors: [{ msg: 'User not found' }] });
        } 

        return res.status(200).json({
            data: {
                msg: 'User information and orders:',
                userId: user._id,
                name: user.name,
                email: user.email,
                order: user.orders
            }
        });
    } catch (error) {
        //console.error(error);
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
                select: 'name email',
            });

        if (!order) {
            return res.status(404).json({ errors: [{ msg: "Order not found or access denied" }] });
        }

        // Check if an invoice already exists for this order
        const existingInvoice = await Invoice.findOne({ orderId, userId: req.user._id });
        if (existingInvoice) {
            return res.status(200).json({
                message: 'Invoice already exists',
                pdfUrl: `/api/invoices/${path.basename(existingInvoice.filePath)}`,
            });
        }

        // Generate PDF from HTML
        const pdfPath = await buildPDFfromHTML(order);

        // Save the invoice metadata in the database
        const invoice = new Invoice({
            userId: req.user._id,
            orderId: order._id,
            filePath: pdfPath,
        });
        await invoice.save();

        // Optionally send the invoice via email
        await sendInvoiceEmail(order, order.userId.email, pdfPath);

        return res.status(201).json({
            message: 'Invoice generated successfully',
            pdfUrl: `/api/invoices/${path.basename(pdfPath)}`,
        });
    } catch (error) {
        return res.status(500).json({
            errors: [{ msg: "Error generating invoice" }],
        });
    }
};

// in browser I use ModHeader to put access token and check routes 
exports.invoices = async (req, res) => {
    const { filename } = req.params;
    const download = req.query.download === 'true'; // I need to add ?download=true to download file

    try {
        // Check if the invoice exists in the database
        const invoice = await Invoice.findOne({
            filePath: path.join(invoicesDir, filename),
            userId: req.user._id, // Ensure the invoice belongs to the authenticated user
        });

        if (!invoice) {
            return res.status(404).json({ errors: [{ msg: 'Invoice not found or access denied' }] });
        }

        // Check if the file exists on the server
        const filePath = invoice.filePath;
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ errors: [{ msg: 'Invoice file not found on server' }] });
        }

        if (download) {
            // Send the file as an attachment (download)
            return res.download(filePath, filename, (err) => {
                if (err) {
                    return res.status(500).json({ errors: [{ msg: 'Could not download the file.' }] });
                }
            });
        } else {
            // Send the file inline (to view in the browser)
            res.sendFile(filePath, (err) => {
                if (err) {
                    return res.status(500).json({ errors: [{ msg: 'Could not view the file.' }] });
                }
            });
        }
    } catch (error) {
        return res.status(500).json({ errors: [{ msg: 'Internal server error.' }] });
    }
};








