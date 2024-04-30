const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const donationRequestSchema = new Schema({
  donationID: {
    type: String,
    required: true,
  },
  requesterName: {
    type: String,
    required: true,
  },
  requesterEmail: {
    type: String,
    required: true,
  },
  requesterContact: {
    type: Number,
    required: true,
  },
  requestDescription: {
    type: String,
    required: true,
  },
  requestStatus: {
    type: String,
    default: "pending",
  },
});

const DonationRequest = mongoose.model(
  "DonationRequest",
  donationRequestSchema
);
module.exports = DonationRequest;
