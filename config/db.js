const mongoose = require("mongoose");

mongoose
  .connect(process.env.MONGO_URI, {
    // No need to include useNewUrlParser or useUnifiedTopology
  })
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((error) => {
    console.error("Connection error:", error);
  });
