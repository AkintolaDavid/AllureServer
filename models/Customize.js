const mongoose = require("mongoose");

const CustomizeSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true,
  },
  BUDGET: {
    type: String,
    required: true,
  },
  engraving: {
    type: String,
    required: true,
  },
  jewelryType: {
    type: String,
  },
  materialType: {
    type: String,
  },
  engravingText: {
    type: String,
  },
  engravingPart: {
    type: String,
  },
  moreInfo: {
    type: String,
  },
  fontStyle: {
    type: String,
  },
  images: {
    type: [String], // Store URLs as an array for multiple images
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now, // Automatically set the date when the document is created
  },
});

// Create a model from the schema
const Customize = mongoose.model("Customize", CustomizeSchema);

module.exports = Customize;
