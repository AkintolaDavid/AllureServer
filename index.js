const axios = require("axios");
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");

const cors = require("cors");
const multer = require("multer");
const path = require("path");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const connectDB = require("./config/db"); // MongoDB connection logic
const mongojs = require("mongojs");
const fs = require("fs");
const db = mongojs("allureDB", ["products", "users", "customizes", "otps"]);
// Assuming 'allureDB' is your database name

const app = express();
const PORT = process.env.PORT || 5000;

const corsOptions = {
  origin: [
    "https://allure-frontend-mu.vercel.app",
    "https://allurefrontend.onrender.com",
  ],
  methods: "GET,POST,PUT,DELETE", // Specify allowed HTTP methods
  credentials: true, // Allow credentials (if you're using cookies or sessions)
};

app.use(cors(corsOptions));

// Use express.json() middleware to parse JSON requests
app.use(express.json());

// Session configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET, // Replace with a secure secret
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI, // Use your MongoDB connection string
    }),
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 1 day (adjust as needed)
    },
  })
);

// Connect to the database
connectDB();

// Increase limit to 10MB for JSON and URL encoded data
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"];

  console.log("Token received:", token);

  if (!token) {
    return res
      .status(403)
      .json({ message: "Please log in before submitting the form!" });
  }

  jwt.verify(token.split(" ")[1], process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.log("Token verification failed:", err);
      return res
        .status(401)
        .json({ message: "Invalid token! Please log in again." });
    }

    req.userId = decoded.id; // Change to 'id' since the token contains 'id' not 'userId'
    console.log("Token verified. User ID:", decoded.id);
    next();
  });
};
const verifyAdminToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1]; // Get token from header
  if (!token) return res.status(403).json({ message: "Access denied" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    if (user.role !== "admin")
      return res.status(403).json({ message: "Access denied" });
    req.user = user; // Save user data for later use
    next();
  });
};
// Cloudinary configuration
const cloudinary = require("cloudinary").v2;
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});
const storage = multer.memoryStorage(); // Use memory storage for direct upload to Cloudinary

const upload = multer({
  storage: storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // Limit the file size to 2MB
  fileFilter: function (req, file, cb) {
    const filetypes = /jpeg|jpg|png/;
    const extname = filetypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    const mimetype = filetypes.test(file.mimetype);

    if (extname && mimetype) {
      return cb(null, true);
    } else {
      cb("Error: Only images are allowed (JPEG/PNG).");
    }
  },
});

const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  category: { type: String, required: true },
  gender: { type: String, required: true },
  description: { type: String, required: true },
  images: [String], // Array of Cloudinary image URLs
});

const Product = mongoose.model("Product", ProductSchema);

// Route for handling product creation
app.post("/api/uploadproducts", verifyAdminToken, async (req, res) => {
  const { name, price, category, gender, images, description } = req.body;

  // Debugging: Log received data
  console.log("Received data:", {
    name,
    price,
    category,
    gender,
    images,
    description,
  });

  if (
    !name ||
    !price ||
    !category ||
    !gender ||
    !description ||
    !images.length
  ) {
    return res.status(400).json({ message: "All fields are required." });
  }

  try {
    const newProduct = new Product({
      name,
      price,

      category,
      gender,
      images, // Directly use the image URLs sent from the frontend
      description,
    });

    await newProduct.save();
    res
      .status(200)
      .json({ message: "Product created successfully", product: newProduct });
  } catch (error) {
    console.error("Error saving product:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});
app.get("/api/products", async (req, res) => {
  try {
    let query = {};

    const products = await Product.find(query);

    res.status(200).json({ products });
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});
// Add this to your server code
app.get("/api/products/:id", async (req, res) => {
  try {
    const productId = req.params.id;
    const product = await Product.findById(productId); // Use findById to get the product

    if (!product) {
      return res.status(404).json({ message: "Product not found" });
    }

    res.status(200).json({ product });
  } catch (error) {
    console.error("Error fetching product:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Route for fetching 10 random products
app.get("/api/getproducts", async (req, res) => {
  try {
    // Use aggregation to randomly select 10 products
    const products = await Product.aggregate([{ $sample: { size: 10 } }]);

    res.status(200).json(products); // Send products to frontend
  } catch (error) {
    console.error("Error fetching random products:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.get("/api/getlikedproducts", (req, res) => {
  db.products.find({ liked: true }, (err, docs) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(docs);
    }
  });
});

app.post("/toggleLike", (req, res) => {
  const { productId, liked } = req.body;

  db.products.update(
    { _id: mongojs.ObjectId(productId) },
    { $set: { liked: liked } },
    (err, doc) => {
      if (err) {
        return res
          .status(500)
          .send({ message: "Error updating product like status" });
      }
      return res
        .status(200)
        .send({ message: "Like status updated", product: doc });
    }
  );
});
app.post(
  "/api/upload",
  verifyAdminToken,
  upload.array("images", 2),
  (req, res) => {
    const images = req.files; // This should be an array of files
    const userId = req.body.userId; // Ensure you are getting the userId if needed

    if (!images || images.length === 0) {
      return res.status(400).json({ message: "No images uploaded." });
    }

    console.log("Images:", images);
    console.log("User ID:", userId);

    // Process the images as needed
    // e.g., upload to Cloudinary, save paths to your database, etc.

    res.status(200).json({ message: "Images uploaded successfully.", images });
  }
);

// Import Cloudinary config

// Define the schema for Customize
const CustomizeSchema = new mongoose.Schema({
  userId: String,
  BUDGET: String,
  engraving: String,
  jewelryType: String,
  materialType: String,
  engravingText: String,
  engravingPart: String,
  moreInfo: String,
  fontStyle: String,
  fullname: String,
  email: String,
  phonenumber: String,
  images: [String], // Store URLs as an array
});

// Create a model for Customize
const Customize = mongoose.model("Customize", CustomizeSchema);
app.get("/api/test", (req, res) => {
  res.json({ message: "API is working!", timestamp: new Date() });
});

app.get("/api/customizes", (req, res) => {
  res.setHeader(
    "Access-Control-Allow-Origin",
    "https://allure-frontend-mu.vercel.app"
  );
  res.setHeader("Access-Control-Allow-Credentials", "true");

  db.customizes.find((err, customizations) => {
    if (err) {
      return res.status(500).json({ error: "Failed to fetch customizations" });
    }

    return res.json(customizations);
  });
});

// Assuming you're using Express and mongojs
app.get("/api/getuser/:userId", async (req, res) => {
  const { userId } = req.params;
  try {
    const user = await db
      .collection("users")
      .findOne({ _id: mongojs.ObjectId(userId) });
    if (user) {
      res.json({ username: user.fullName }); // Assuming 'fullName' is the field storing the user's name
    } else {
      res.status(404).json({ error: "User not found" });
    }
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/verify-payment", async (req, res) => {
  const { reference } = req.body;

  try {
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`, // Use your Paystack secret test key
        },
      }
    );

    if (response.data.data.status === "success") {
      return res
        .status(200)
        .json({ status: "success", message: "Payment verified successfully" });
    } else {
      return res
        .status(400)
        .json({ status: "error", message: "Payment verification failed" });
    }
  } catch (error) {
    console.error("Error verifying payment: ", error);
    return res
      .status(500)
      .json({ status: "error", message: "Error verifying payment" });
  }
});

// Endpoint to customize jewelry
app.post("/api/customizejewelry", verifyToken, async (req, res) => {
  try {
    const {
      images, // Expecting this to be an array of image URLs
      BUDGET,
      engraving,
      jewelryType,
      materialType,
      engravingText,
      engravingPart,
      moreInfo,
      fontStyle,
      fullname,
      email,
      phonenumber,
    } = req.body;

    const jewelryData = {
      userId: req.userId, // From the token
      BUDGET,
      engraving,
      jewelryType,
      materialType,
      engravingText,
      engravingPart,
      moreInfo,
      fontStyle,
      fullname,
      email,
      phonenumber,
      images, // Store Cloudinary URLs directly
    };

    // Save jewelryData to MongoDB
    const customized = new Customize(jewelryData);
    await customized.save();

    res.json({
      message: "Customization order successful.",
      data: {
        images: jewelryData.images, // Include the image URLs in the response
      },
    });
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ message: "Server error. Unable to save customization." });
  }
});

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  phone: String,
  fullName: String,
});

// Create a model for the User
const User = mongoose.model("User", userSchema); // This line must come first

// Prevent OverwriteModelError
app.post("/api/signup", async (req, res) => {
  const { email, phone, password, fullName } = req.body;

  console.log("Received signup request with fullName:", fullName);

  try {
    // Check if the password is less than 6 characters
    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters long" });
    }

    const existingUser = await User.findOne({ $or: [{ phone }, { email }] });
    console.log("User found:", existingUser);

    if (existingUser) {
      if (existingUser.phone === phone) {
        return res
          .status(400)
          .json({ message: "Phone number is already registered" });
      }
      if (existingUser.email === email) {
        return res.status(400).json({ message: "Email is already registered" });
      }
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      email,
      phone,
      password: hashedPassword,
      fullName,
    });

    await newUser.save();

    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, {
      expiresIn: "24h",
    });

    console.log(
      "User registered successfully with fullName:",
      newUser.fullName
    );

    res.status(201).json({
      message: "User registered successfully",
      token,
      user: {
        id: newUser._id,
        email: newUser.email,
        phone: newUser.phone,
        fullName: newUser.fullName,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Login Endpoint
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });

    if (!existingUser) {
      // Specify message for non-existent user
      return res.status(400).json({ message: "Email not registered" });
    }

    const isMatch = await bcrypt.compare(password, existingUser.password);
    if (!isMatch) {
      // Specify message for incorrect password
      return res.status(400).json({ message: "Invalid password" });
    }

    console.log("Login successful for user:", existingUser.email);
    const token = jwt.sign({ id: existingUser._id }, process.env.JWT_SECRET, {
      expiresIn: "24h",
    });
    console.log(token);
    return res.status(200).json({
      message: "Login successful",
      token,
      fullName: existingUser.fullName,
      email: existingUser.email, // Add this line to send the email
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Server error" });
  }
});
// Generate a transporter for sending emails
const transporter = nodemailer.createTransport({
  service: "gmail", // Use Gmail as your email service provider
  auth: {
    user: process.env.EMAIL_USER, // Your email
    pass: process.env.EMAIL_PASS, // Add this to authenticate the email
  },
});

// Forgot password route
app.post("/api/forgotpassword", async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(404).send("User not found");
  }

  // Generate JWT token
  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
    expiresIn: "15m", // Token expires in 15
  });

  // Set the reset token and its expiration in the user document
  user.resetToken = token;
  user.resetTokenExpiration = Date.now() + 900000; // 15 minutes

  // Save the updated user with the token and expiration
  await user.save();

  // URL for resetting password, sent to the user's email
  const resetUrl = `https://allure-frontend-mu.vercel.app/reset-password/${token}`;

  // Send reset password email with nodemailer
  try {
    await transporter.sendMail({
      to: email,
      subject: "ALLURE Password Reset",
      html: `
      <div
      style="
        font-family: Arial, sans-serif;
        max-width: 600px;
        margin: 0 auto;
        padding: 20px;
        border: 1px solid #ddd;
        border-radius: 10px;
        background-color: #f1f2f4;
      "
    >
      <table
        width="100%"
        cellpadding="0"
        cellspacing="0"
        border="0"
        style="max-width: 600px; margin: 0 auto; background-color: #fff; text-align: center; border-collapse: collapse;"
      >
        <tr>
          <td
            style="
              background-color: #252526;
              color: white;
              padding: 20px;
              font-size: 23px;
              font-weight: 600;
              border-top-left-radius: 12px;
              border-top-right-radius: 12px;
            "
          >
          Reset ALLURE password
          </td>
        </tr>
        <tr>
          <td
            style="
              padding: 20px;
              font-size: 25px;
              font-weight: 700;
              color: black;
              text-align: center;
            "
          >
          You have requested for password reset. Please click the link below to change your password. 
          </td>
        </tr>
      
        <tr>
          <td style="padding: 10px 20px; font-size: 14px; font-weight: 700; color: black; text-align: center;">
          <a
          href="${resetUrl}"
          style="
            color: red;
            text-decoration: underline;
            font-size: 21px;
            font-weight: bold;
            
          "
        >
          Change Password
        </a> </tr>
    
        
        <tr>
          <td style="padding: 10px 20px; font-size: 14px; color: #777; text-align: center;">
            This email was generated automatically. Please do not reply directly.
          </td>
        </tr>
      </table>
    </div>
    

    
      `,
    });
    res.send("Password reset email sent");
  } catch (err) {
    console.error("Error sending email:", err);
    res.status(500).send("Error sending reset email");
  }
});

// Reset password route
app.post("/api/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  // Check if the password has at least 6 characters
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).send("Password must be at least 6 characters long");
  }

  let userId;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    userId = decoded.userId;
  } catch (err) {
    return res.status(400).send("Invalid or expired token");
  }

  const user = await User.findById(userId);
  if (!user) {
    return res.status(400).send("Invalid or expired token");
  }

  if (user.resetTokenExpiration < Date.now()) {
    return res.status(400).send("Invalid or expired token");
  }

  user.password = await bcrypt.hash(newPassword, 10);
  user.resetToken = undefined; // Clear the reset token
  user.resetTokenExpiration = undefined; // Clear the expiration date
  await user.save();

  res.send("Password has been reset");
});

// Contact form route
app.post("/api/contact", async (req, res) => {
  const { name, email, message } = req.body;

  // Validate input
  if (!name || !email || !message) {
    return res.status(400).send("All fields are required.");
  }

  try {
    await transporter.sendMail({
      to: process.env.EMAIL_USER, // Send to the admin's email
      subject: "Allure New Contact Form Submission",
      html: `
      <div
      style="
        font-family: Arial, sans-serif;
        max-width: 600px;
        margin: 0 auto;
        padding: 20px;
        border: 1px solid #ddd;
        border-radius: 10px;
        background-color: #f1f2f4;
      "
    >
      <table
        width="100%"
        cellpadding="0"
        cellspacing="0"
        border="0"
        style="max-width: 600px; margin: 0 auto; background-color: #fff; text-align: center; border-collapse: collapse;"
      >
        <tr>
          <td
            style="
              background-color: #252526;
              color: white;
              padding: 20px;
              font-size: 23px;
              font-weight: 600;
              border-top-left-radius: 12px;
              border-top-right-radius: 12px;
            "
          >
            ALLURE Contact Form Submission
          </td>
        </tr>
        <tr>
          <td
            style="
              padding: 20px;
              font-size: 32px;
              font-weight: 700;
              color: black;
              text-align: left;
            "
          >
            You have received a new message from:
          </td>
        </tr>
        <tr>
          <td style="padding: 10px 20px; font-size: 22px; font-weight: 700; color: black; text-align: left;">
            Name: ${name}
          </td>
        </tr>
        <tr>
          <td style="padding: 10px 20px; font-size: 22px; font-weight: 700; color: black; text-align: left;">
            Email: <a href="mailto:${email}" style="color: #4caf50;">${email}</a>
          </td>
        </tr>
        <tr>
          <td style="padding: 10px 20px; font-size: 22px; font-weight: 700; color: black; text-align: left;">
            Message:
          </td>
        </tr>
        <tr>
          <td style="padding: 10px 20px; background-color: #f9f9f9; font-size: 22px; color: black; text-align: left;">
            ${message}
          </td>
        </tr>
        <tr>
          <td style="padding: 10px 20px; font-size: 14px; color: #777; text-align: left;">
            This email was generated automatically. Please do not reply directly.
          </td>
        </tr>
      </table>
    </div>
    

    
      `,
    });
    res.status(200).send({ message: "Contact message sent successfully!" });
  } catch (err) {
    console.error("Error sending email:", err);
    return res.status(500).send("Error sending contact message.");
  }
});

const Otp = require("./models/Otp"); // Make sure the model is imported correctly

// Function to check if the OTP is valid

const sendOtpToEmail = async (email, otp) => {
  const transporter = nodemailer.createTransport({
    service: "gmail", // Use your email provider's SMTP service
    auth: {
      user: process.env.EMAIL_USER, // Your email address
      pass: process.env.EMAIL_PASS, // Your email password or app password
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "ALLURE OTP Code",
    html: `
      <div
      style="
        font-family: Arial, sans-serif;
        max-width: 600px;
        margin: 0 auto;
        padding: 20px;
        border: 1px solid #ddd;
        border-radius: 10px;
        background-color: #f1f2f4;
      "
    >
      <table
        width="100%"
        cellpadding="0"
        cellspacing="0"
        border="0"
        style="max-width: 600px; margin: 0 auto; background-color: #fff; text-align: center; border-collapse: collapse;"
      >
        <tr>
          <td
            style="
              background-color: #252526;
              color: white;
              padding: 20px;
              font-size: 23px;
              font-weight: 600;
              border-top-left-radius: 12px;
              border-top-right-radius: 12px;
            "
          >
          ALLURE OTP Code
          </td>
        </tr>
        <tr>
          <td
            style="
              padding: 20px;
              font-size: 32px;
              font-weight: 700;
              color: black;
              text-align: center;
            "
          >
          Here's your one-time code for ALLURE
          </td>
        </tr>
      
        <tr>
          <td style="padding: 10px 20px; font-size: 14px; font-weight: 700; color: black; text-align: center;">
          Use this passcode to verify the email address of Admin. It will expire in 10 minutes.   </td>
        </tr>
        <tr>
          <td style="padding: 10px 20px; font-size: 22px; font-weight: 700; color: black; text-align: center;">
          ${otp}
          </td>
        </tr>
        
        <tr>
          <td style="padding: 10px 20px; font-size: 14px; color: #777; text-align: center;">
            This email was generated automatically. Please do not reply directly.
          </td>
        </tr>
      </table>
    </div>
    

    
      `,
  };

  // Send email
  await transporter.sendMail(mailOptions);
};

app.post("/api/send-otp", async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(1000 + Math.random() * 9000);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 30 minutes from now

  // Save the OTP and expiration time in the database
  const otpEntry = new Otp({ email, otp, expiresAt });
  await otpEntry.save();

  // Send the OTP to the email (assume you have this implemented)
  try {
    await sendOtpToEmail(email, otp);
  } catch (error) {
    return res.status(500).json({ message: "Error sending OTP" });
  }
  res.status(200).json({ success: true, message: "OTP sent successfully" });
});
app.post("/api/verify-otp", async (req, res) => {
  const { otp } = req.body;
  try {
    const otpRecord = await Otp.findOne({ otp });
    if (!otpRecord) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }

    const now = new Date();
    if (otpRecord.expiresAt < now) {
      return res
        .status(400)
        .json({ success: false, message: "OTP has expired" });
    }

    const token = jwt.sign(
      { role: "admin", email: otpRecord.email },
      process.env.JWT_SECRET,
      { expiresIn: "20m" }
    );

    // Try to delete OTP and catch any errors related to deletion
    try {
      await Otp.deleteOne({ _id: otpRecord._id });
    } catch (deleteError) {
      console.error("Error deleting OTP:", deleteError.message);
      return res.status(500).json({
        success: false,
        message: "Failed to delete OTP after verification",
      });
    }

    // Return the token upon successful OTP verification
    return res.json({
      success: true,
      token,
      message: "OTP verified successfully",
    });
  } catch (error) {
    console.error("Error verifying OTP:", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
});

// Use user routes for other user-related functionality
// app.use("/api/users", userRoutes);

// Start the server

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
