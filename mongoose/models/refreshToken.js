const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const RefreshTokenSchema = new Schema({
    token: {
        type: String,
        required: true
    },
    user: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    expiresAt: {
        type: Date,
        required: true
    }
});

module.exports = mongoose.model('RefreshToken', RefreshTokenSchema);
