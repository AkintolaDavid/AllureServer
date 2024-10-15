// const bcrypt = require("bcrypt");
// const jwt = require("jsonwebtoken");
// const User = require("../models/User");

// exports.signup = async (req, res) => {
//   const { email, phone, password, fullName } = req.body; // Include fullName in the destructuring

//   console.log("Received signup request with fullName:", fullName); // Log the received fullName

//   try {
//     // Check if the user already exists
//     const existingUser = await User.findOne({ $or: [{ phone }, { email }] });
//     if (existingUser) {
//       if (existingUser.phone === phone) {
//         return res
//           .status(400)
//           .json({ message: "Phone number is already registered" });
//       }
//       if (existingUser.email === email) {
//         return res.status(400).json({ message: "Email is already registered" });
//       }
//     }

//     // Hash the password
//     const salt = await bcrypt.genSalt(10);
//     const hashedPassword = await bcrypt.hash(password, salt);

//     // Create a new user
//     const newUser = new User({
//       email,
//       phone,
//       password: hashedPassword,
//       fullName, // Store fullName in the user object
//     });

//     // Save the user in the database
//     await newUser.save();

//     // Optionally generate a token (if your app requires login right after signup)
//     const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, {
//       expiresIn: "1h", // Set token expiration time
//     });

//     // Log the fullName that is being sent back
//     console.log(
//       "User registered successfully with fullName:",
//       newUser.fullName
//     );

//     // Return a success message along with token and user details (excluding password)
//     res.status(201).json({
//       message: "User registered successfully",
//       token,
//       user: {
//         id: newUser._id,
//         email: newUser.email,
//         phone: newUser.phone,
//         fullName: newUser.fullName, // Return full name
//       },
//     });
//   } catch (error) {
//     console.error(error); // Log the error for debugging purposes
//     res.status(500).json({ message: "Server error" });
//   }
// };
// exports.login = async (req, res) => {
//   const { email, password } = req.body;

//   try {
//     // Check if the user exists
//     const user = await User.findOne({ email }); // Fetch user from the database
//     if (!user) {
//       return res.status(400).json({ message: "User not found" });
//     }

//     // Compare passwords
//     const isMatch = await bcrypt.compare(password, user.password);
//     if (!isMatch) {
//       return res.status(400).json({ message: "Invalid credentials" });
//     }

//     // Log the fullName being returned
//     console.log("Login successful for user:", user.email);
//     console.log("Full name retrieved during login:", user.fullName); // Log fullName

//     // Generate token
//     const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
//       expiresIn: "1h",
//     });

//     // Return user data along with the token
//     return res.status(200).json({
//       token: token,
//       fullName: user.fullName, // Send full name in response
//     });
//   } catch (error) {
//     console.error(error); // Log error for debugging
//     res.status(500).json({ message: "Server error" });
//   }
// };
