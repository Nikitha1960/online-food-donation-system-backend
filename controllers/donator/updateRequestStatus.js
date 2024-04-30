const {
  sendAcceptedEmail,
  sendRejectedEmail,
} = require("../../common/sendEmail");
const Donation = require("../../models/donation.model");
const DonationRequest = require("../../models/donationRequest.model");

const acceptDonationRequest = async (req, res) => {
  try {
    const updateRequest = {
      requestStatus: "accepted",
    };
    await DonationRequest.findByIdAndUpdate(req.params.id, updateRequest)
      .then(() => {
        console.log(req.body);
        sendAcceptedEmail(req.body.email, req.body.title);
        res.status(201).json({
          message: "Requetsted updated",
        });
      })
      .catch((err) => {
        res.status(201).json({
          message: err,
        });
      });
  } catch (error) {
    console.log(error);
  }
};

const rejectDonationRequest = async (req, res) => {
  try {
    const updateRequest = {
      requestStatus: "rejected",
    };
    await DonationRequest.findByIdAndUpdate(req.params.id, updateRequest)
      .then((request) => {
        sendRejectedEmail(req.body.email, req.body.title);
        console.log(request);
        res.status(201).json({
          message: "Requetsted updated",
        });
      })
      .catch((err) => {
        res.status(201).json({
          message: err,
        });
      });
  } catch (error) {
    console.log(error);
  }
};

module.exports = {
  acceptDonationRequest,
  rejectDonationRequest,
};
