const passport = require('passport');
const { Strategy } = require('passport-local');
const StrategyJWT = require('passport-jwt').Strategy;
const ExtractJWT = require('passport-jwt').ExtractJwt;


const keys = process.env.ACCESS_TOKEN_SECRET;
const User = require('../mongoose/models/user');

const accessTokenOptions = {
    jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
    secretOrKey: keys
}

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

            if (!user) {
                return done(null, false); // User not found
            }

            // Check if the `random` is in `agents` (regular session) or `tempAgents` (temporary session)
            const isAccessToken = user.agents.some(agent => agent.random === jwt_payload.random);
            const isTempToken = user.tempAgents.some(tempAgent => tempAgent.random === jwt_payload.random);

            if (isAccessToken) {
                // Attach the random identifier from `agents` and mark as a regular session
                user.random = jwt_payload.random;
                user.sessionType = 'access';  
                return done(null, user);

            } else if (isTempToken) {
                // Attach the random identifier from `tempAgents` and mark as a temporary session
                user.random = jwt_payload.random;
                user.sessionType = 'temporary';  
                return done(null, user);
            } else {
                // If neither is matched, return an unauthorized response
                return done(null, false);
            }
        } catch (error) {
            return done(error, false); // Server error
        }
    })
);

    
}

