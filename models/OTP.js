const mongoose = require('mongoose');

const otpSchema = new mongoose.Schema({
    ref: {
        type: String,
        required: true,
        unique: true
    },
    otp_hash: {
        type: String,
        required: true
    },
    identifier: {
        type: String,
        required: true
    },
    expires_at: {
        type: Date,
        required: true,
        default: () => new Date(Date.now() + 5 * 60 * 1000) // Default 5 mins
    }
});

// TTL Index: Automatically delete documents after 'expires_at' time
otpSchema.index({ expires_at: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('OTP', otpSchema);
