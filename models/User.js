const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  fullName: { type: String, required: true },
});

// Hash the password before saving the user
// userSchema.pre("save", async function (next) {
//   if (!this.isModified("password")) return next();
//   const salt = await bcrypt.genSalt(10);
//   this.password = await bcrypt.hash(this.password, salt);
//   next();
// });

const User = mongoose.model("User", userSchema);
module.exports = User;
// const mongoose = require("mongoose");

// const userSchema = new mongoose.Schema({
//   email: { type: String, required: true },
//   password: { type: String, required: true },
//   // resetToken: { type: String, default: null },
//   // resetTokenExpiration: { type: Date, default: null },
//   phone: String,
//   fullName: String,
// });

// const User = mongoose.model("User", userSchema);
// module.exports = User;
