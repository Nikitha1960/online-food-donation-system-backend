const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const RequesterSchema = new Schema({
  firstName: {
    type: String,
    required: true,
  },
  lastName: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  contactNumber: {
    type: Number,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },

  roles: {
    type: String,
    required: true,
    default: "1984",
  },
});

const Requester = mongoose.model("individual", RequesterSchema);
module.exports = Requester;
