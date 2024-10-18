const passport = require('passport');
const { Strategy } = require('passport-local');
const StrategyJWT = require('passport-jwt').Strategy;
const ExtractJWT = require('passport-jwt').ExtractJwt;


const keys = process.env.ACCESS_TOKEN_SECRET;
//const keys2 = process.env.REFRESH_TOKEN_SECRET;
const User = require('../mongoose/models/user');

const accessTokenOptions = {
    jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
    secretOrKey: keys
}

passport.serializeUser((user, done) => { // to tell passport how to serialize user data into the session (it stores user ID to session data)
    done(null, user.id);
})

passport.deserializeUser(async (id, done) => { // to take that ID and unpack, reveal who the actual user is (searcheas for the user in database or in array) and then it stores that user object into the request object (then we can reference request.user when we make requests)
    try {
        const findUser = await User.findById(id);
        if (!findUser) throw new Error("User Not Found");
        done(null, findUser);
    } catch (err) {
        done(err, null);
    }
})

module.exports = (passport) => {
    passport.use(
        "local", // validates user - checks if user exists and the passwords match
        new Strategy(
            {
                usernameField: 'email',
            }, 
            async (email, password, done) => {
                try {
                    const findUser = await User.findOne({ email });
                    if (!findUser) {
                        // user not found
                        return done(null, false); //null - no errors in server side, false - eroor in user auth
                    }
                    const isMatch = await findUser.comparePassword(password);
                    if (!isMatch) {
                        // password does't match
                        return done(null, false);
                    };
                    if (findUser.deletedAt) {
                        // user delited
                        return done(null, false);
                    }
                    done(null, findUser);
                } catch (err) {
                    done(err, null); // err -error in server side, null - no user returned
                }
            }
        
        )
    );

    passport.use(
        'jwt',
        new StrategyJWT(accessTokenOptions, async (jwt_payload, done) => {
            try {
                const user = await User.findById(jwt_payload._id);

                // Check for random field in the payload
                const validSession = user.agents.some(agent => agent.random === jwt_payload.random);

                if (!validSession) {
                    // invalid token
                    return done(null, false);
                }
    
                if (user) {
                    return done(null, user);
                } else {
                    console.log("Error in user authentication");
                    // user not found
                    return done(null, false); // null - no server errors, false - error in user auth
                }
            } catch (error) {
                // error - error in server side, false - false for user
                return done(error, false);
            }
        })
    );
    
}

