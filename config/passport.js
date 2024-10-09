const StrategyJWT = require('passport-jwt').Strategy;
const ExtractJWT = require('passport-jwt').ExtractJwt;
// const RefreshToken = require('../mongoose/models/RefreshToken');
// const customExtractJWT = (req) => {
//     // Return the refresh token from the request body
//     if (req && req.body && req.body.refreshToken) {
//         return req.body.refreshToken;
//     }
//     return null; // Return null if refresh token is not found
// };

const keys = process.env.ACCESS_TOKEN_SECRET;
const keys2 = process.env.REFRESH_TOKEN_SECRET;
const User = require('../mongoose/models/user');

const accessTokenOptions = {
    jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
    secretOrKey: keys
}
// const refreshTokenOptions = {
//     jwtFromRequest: customExtractJWT,
//     secretOrKey: keys2
// }

module.exports = (passport) => {
    passport.use(
        'jwt',
        new StrategyJWT(accessTokenOptions, async(jwt_payload, done) => {
            const user = await User.findById(jwt_payload._id)
            if(user){
                return done(null, user)
            } else {
                console.log("Error in user authentication");
                //return done(null, false); 
            }
        })
    )

    // passport.use(
    //     'jwt-refresh',
    //     new StrategyJWT(refreshTokenOptions, async (jwt_payload, done) => {
    //         try {
    //             const refreshToken = jwt_payload.refreshToken; // Get the refresh token from payload
                
    //             if (!refreshToken) {
    //                 return done(null, false, { message: 'Refresh token not provided' });
    //             }

    //             // Check if the refresh token exists in the DB
    //             const storedRefreshToken = await RefreshToken.findOne({ token: refreshToken });

    //             if (!storedRefreshToken) {
    //                 return done(null, false, { message: 'Invalid refresh token' });
    //             }

    //             // Check if the user exists
    //             const user = await User.findById(jwt_payload._id);
    //             if (user) {
    //                 return done(null, user);
    //             } else {
    //                 return done(null, false, { message: 'User not found' });
    //             }
    //         } catch (error) {
    //             console.log("Error in refreshing JWT", error);
    //             return done(error, false);
    //         }
    //     })
    // );
    
}

