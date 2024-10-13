const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// Define the schema for blacklisted tokens
const BlacklistedTokenSchema = new Schema({
    token: {
        type: String,
        required: true,
        unique: true,  // Ensure each token is unique
    },
    blacklistedAt: {
        type: Date,
        default: Date.now,
    }
});


// Create the model from the schema and export it
const BlacklistedToken = mongoose.model('BlacklistedToken', BlacklistedTokenSchema);
module.exports = BlacklistedToken;
