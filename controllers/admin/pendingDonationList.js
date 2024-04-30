const Donation = require("../../models/donation.model");

const getAllPendingDonations = async (req, res) => {
    await Donation.find({ status: "pending"})
      .then((donations) => {
        res.json(donations);
      })
      .catch((err) => {
        res.json({
          errror: err,
        });
      });
  };

  module.exports={
    getAllPendingDonations
  };