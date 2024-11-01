const User = require('@modelsUser');
const passport = require('passport');
const crypto = require('crypto');
const { validationResult, matchedData, body } = require('express-validator');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const keys = process.env.ACCESS_TOKEN_SECRET;
const keys2 = process.env.REFRESH_TOKEN_SECRET;
const accessTokenExpiry = process.env.JWT_ACCESS_TOKEN_EXPIRY // 10min; 
const Order = require('../mongoose/models/order');
const Product = require('../mongoose/models/product');
const userModel = require('../mongoose/models/user')
const orderModel = require('../mongoose/models/order')



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
        body("role").optional().isIn(['user', '1534']).withMessage('Invalid role') 
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
                                userId: user.id
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
       
        passport.authenticate("local", async (err, user, info) => { // here i only use passport for user authentication, but don't attach user to the session 
            //console.log("err, user, info", err, user, info)
            
            if (err) {
                return response.status(500).send({ errors: [{ msg: "Internal Server Error" }] });
            }
            
            if (!user) {
                return response.status(401).send({ errors: [{ msg: "Access Denied" }] });
            }

            const sessionRandom = crypto.randomBytes(16).toString('hex');

            if (!user.agents) {
                user.agents = [];
            }
            
            const random = sessionRandom
            user.agents.push({
                random
            })

            try {
                await user.save(); // Save the updated agents array to the database
            } catch (saveError) {
                console.error("Error saving user agents:", saveError);
                return response.status(500).send({ errors: [{msg: "Error saving user agents"}] });
            } 

            const payload = { _id: user._id, random };

            let accessToken, refreshToken;
            try {
                accessToken = jwt.sign(payload, keys, { expiresIn: accessTokenExpiry });
                refreshToken = jwt.sign(payload, keys2);
            } catch (err) {
                return response.status(500).send({ errors: [{msg: "Error generating tokens"}] });
            }

            try {
                return response.json({
                    status: true,
                    msg: "Logged in successfully",
                    accessToken: accessToken,
                    refreshToken: refreshToken,
                    data: {
                        user: user.name,
                        email: user.email,
                        _id: user._id
                    }
                });
            } catch (error) {
                console.log("Error in saving refresh token:", error);
                return response.status(500).send({ errors: [{msg: "Server error"}] });
            }
        
        })(request, response, next);
    }
    
];  

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
        const random = req.user.agents.find(agent => agent.random)?.random;

        console.log("random before logout", random)
        if (!random) {
            return res.status(401).json({ errors: [{msg: "Unauthorized access."}] });
        }
        req.user.agents = req.user.agents.filter(agent => agent.random !== random); // will remove random from agents array
        console.log("agents after deleting random", req.user.agents)
        await req.user.save();
        return res.status(200).json({ msg: "Logged out successfully" });

    } catch (error) {
        console.log("Error logging out", error);
        return res.status(500).json({ errors: [{msg: "Server error"}] });
    }
};

//Admin Route to Terminate User Sessions
exports.terminateSession = async (req,res) => {
    try {
        const { userId } = req.body; 

        // Validate the userId format
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ errors: [{ msg: 'Invalid user ID format' }] });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ errors: [{msg: 'User not found'}] });
        }
    
        console.log("User agents before:", user.agents);

        const random = user.agents.find(agent => agent.random)?.random;

        console.log("Random value found:", random);

        user.agents = user.agents.filter(agent => agent.random !== random); // will remove random from agents array

        console.log("User agents after:", user.agents);

        await user.save(); // saving to database without random in agents

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

exports.fetchUser = async(req, res) => {
    try {
        const user = await User.findById(req.body.userId) // need to check if id is wrong
            .populate({
                path: 'orders',
                populate: {
                    path: 'products',
                    model: 'Product'
                }
            });
            console.log(user)
            return res.json({ 
                data: {
                    msg: 'User orders', 
                    userId : user._id, 
                    name: user.name,
                    email: user.email,
                    orders: user.orders
                }
            });
    } catch (error) {
        return res.status(500).send({ error: error.message });
    }
}

// exports.addProduct = async (req, res) => {
//     try {
//         const { name, price } = req.body;  

//         const newProduct = new Product({ name, price });
//         await newProduct.save();  

//         return res.status(201).json({ message: 'Product added successfully', product: newProduct });
//     } catch (error) {
//         console.error(error);
//         return res.status(500).send({ error: error.message });
//     }
// };

// exports.createOrder = async (req, res) => {
//     try {
//         const { userId, productIds } = req.body;  // Get user ID and product IDs from request body

//         // Create a new order
//         const newOrder = new Order({ products: productIds });
//         await newOrder.save();

//         // Update the user with the new order
//         await User.findByIdAndUpdate(userId, { $push: { orders: newOrder._id } });

//         return res.status(201).json({ message: 'Order created successfully', order: newOrder });
//     } catch (error) {
//         console.error(error);
//         return res.status(500).send({ error: error.message });
//     }
// };
exports.addProduct = async (req, res) => {
    try {
        const { name, price } = req.body;  

        const newProduct = new Product({ name, price });
        await newProduct.save();  

        //res.status(201).json({ message: 'Product added successfully', product: newProduct });
        let productId = newProduct._id

        // Step 2: Check if the user has an existing order; create one if they don’t
        let order = await Order.findOne({ user: req.user._id });

        if (!order) {
            // If the user has no order, create a new one
            order = new Order({ user: req.user._id, products: [productId] });
            await order.save();

            await User.findByIdAndUpdate(req.user._id, { $push: { orders: order._id } });

        } else {
            // If an order exists, add the new product to the products array
            order.products.push(productId);
            await order.save();
        }

        res.send("products added to order")
    } catch (error) {
        console.error(error);
        res.status(500).send({ error: error.message });
    }

    
}






