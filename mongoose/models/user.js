const { mongoose } = require("mongoose");
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        min: 3
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    password: {
        type: String,
        required: true,
        min: 4,
        max: 20
    },
    // isMfaActive: {
    //     type: Boolean,
    //     required: false
    // },
    twoFactorSecret: {
        type: String
    },
    isTwoFactorVerified: { // to track 2FA status
        type: Boolean,
        default: false // Default is false, meaning 2FA is not verified yet
    },
    role: {
        type: String,
        enum: ['user', 'admin'], 
        default: 'user'
    },
    agents: {
        type: Array,
        default: [] 
    },
    tempAgents: {
        type: Array,
        default: [] 
    },
    order: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Order'
    }]
    
    },
    {
        timestamps: true
    }
);

//Hash password before saving the user document
UserSchema.pre('save', async function (next) {
    const user = this;

    // If the password field is not modified
    if (!user.isModified('password')) {
        return next();
    }

    // Generate a salt and hash the password
    try {
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(user.password, salt);
        user.password = hash;
        next();
    } catch (err) {
        next(err);
    }
});

// Instance method to compare plain password with the hashed password
UserSchema.methods.comparePassword = async function (plainPassword) {
    return bcrypt.compare(plainPassword, this.password);
};

const User = mongoose.model("User", UserSchema);

module.exports = User;