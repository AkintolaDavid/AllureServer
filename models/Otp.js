const mongoose = require("mongoose");
// Assuming you have a schema for OTP
const otpSchema = new mongoose.Schema({
  email: String,
  otp: Number,
  expiresAt: Date,
});

// Create a TTL index on the expiresAt field
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model("Otp", otpSchema);
