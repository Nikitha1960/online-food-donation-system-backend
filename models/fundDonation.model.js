const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const fundDonationSchema = new Schema({
  userID: {
    type: String,
    required: true,
  },
  fundID: {
    type: String,
    required: true,
  },
  organizationID: {
    type: String,
    required: true,
  },
  amount: {
    type: Number,
    required: true,
  },
  donatedDate: {
    type: Date,
    required: true,
    default: Date.now,
  },
});

const FundDonation = mongoose.model("FundDonation", fundDonationSchema);
module.exports = FundDonation;
