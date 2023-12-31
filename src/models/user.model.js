const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    emailVerificationToken: String,
    emailVerified: {
        type: Boolean,
        default: false,
    },
    resetToken: String,
    resetTokenExpiration: Date,
    profilePic: {
        data: Buffer,
        contentType: String,
    },
}, { collection: 'User' });

const User = mongoose.model('User', userSchema);

module.exports = User;
