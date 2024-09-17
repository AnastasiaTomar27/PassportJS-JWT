const StrategyJWT = require('passport-jwt').Strategy
const ExtractJWT = require('passport-jwt').ExtractJwt

const keys = process.env.ACCESS_TOKEN_SECRET;
const User = require('../mongoose/models/user');

const options = {}

options.jwtFromRequest = ExtractJWT.fromAuthHeaderAsBearerToken();
options.secretOrKey = keys;

module.exports = (passport) => {
    passport.use(
        new StrategyJWT(options, async(jwt_payload, done) => {
            const user = await User.findById(jwt_payload._id)
            if(user){
                return done(null, user)
            } else {
                console.log("Error in user authentication")
            }
        })
    )
}

