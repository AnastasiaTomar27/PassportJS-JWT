const User = require('@modelsUser');
//const { validationResult, matchedData, body } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


const keys = process.env.ACCESS_TOKEN_SECRET;


exports.userRegister = async (request, response) => {

    try {
        const { name, email, password } = request.body;

        if(!name) {
            return response.status(400).json({msg: "Name is required!"})
        }
        if(!email) {
            return response.status(400).json({msg: "Email is required!"})
        }
        if(!password || password.length < 4 ) {
            return response.status(400).json({msg: "Password is required and it should be of length 4 - 20!"})
        }
        
        const user = await User.findOne({email})
        if(user) {
            return response.status(400).json({
                msg: "User already exists with this email"
            })
        }

        const newUser = await new User({
            name,
            email,
            password
        })

        await newUser.save()
        return response.status(201).json({
            success: true,
            msg: "User created",
            data: newUser
        })
    } catch (error) {
        console.log("error in user signup")
        return response.status(500).json({msg: "Server error"})
    }
    
}

// added proper validation

// exports.userRegister = [
//         [
//         body("name").notEmpty().isLength({ max: 20 }).withMessage('Name must be maximum of 20 characters.').isString(),
//         body("email").notEmpty().isLength({ max: 20 }).withMessage('Email must be maximum of 20 characters.').isString(),
//         body("password").notEmpty().isLength({ max: 20 }).withMessage('Password must be maximum of 20 characters.').isString()
//             .custom(async (value) => {
//                 const passwordRegex = /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])/;
//                 if (!passwordRegex.test(value)) {
//                     throw new Error(); }
//                 }).withMessage("User password configuration is invalid")  
//         ],
//         async (request, response) => {
//             const result = validationResult(request);
    
//             if (!result.isEmpty()) {
//                 return response.status(400).send({ errors: result.array() });
//             }     
    
//             const data = matchedData(request);
//             const newUser = new User(data);

//             try {
//                 const userAvailable = await User.findOne({username: data.username});
//                 if (userAvailable) {
//                     return res.status(400).json({message: "User already registered!"});
//                 }
//                 const savedUser = await newUser.save();
//                 return response.status(201).send(savedUser);
//             } catch (err) {
//                 console.log(err);
//                 return response.status(400);
//             }
//         }
// ]


// I don't use passport.js here
exports.login = async(req, res) => {
    try {
        // First check if user exists: check email and password 
        const { email, password } = req.body

        const user = await User.findOne({email})

        if(!user) {
            return res.status(400).json({msg: "Invalid credentials"})
        }
        const isMatched = await bcrypt.compare(password, user.password);

        if(!isMatched) {
            return res.status(400).json({msg: "Invalid credentials"})
        }

        // if user exists, then make constatnt payload with the user information(user ID and email)
        const payload = {
            _id: user._id,
            email: user.email
        }

        // now create token for protected routes, for example profile route
        jwt.sign(payload, keys, {expiresIn: '1m'}, (err, token) => {
            if(err){
                return res.json({msg: " Error in generation token"})
            }
            return res.json({
                msg: "Logged in successfully",
                token: token
            })
        })

    } catch (error) {
        console.log("error in log in", error);
        return res.status(500).json({msg: "Server error"})
    }
}  


// I use passport.js here
exports.userProfile = async (req, res) => {
    console.log(req.user);
    const userProfile = await User.findById(req.user._id).select('-password');
    return res.json(userProfile)
}

