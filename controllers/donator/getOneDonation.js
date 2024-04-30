const Donation = require("../../models/donation.model");

const getOneDonationDetails = async (req, res) => {
  try {
    const donationId = req.params.id;
    console.log(donationId);
    await Donation.findOne({ _id: donationId })
      .then((donation) => {
        res
          .status(200)
          .send({ message: "Donation fetched", donation: donation });
      })
      .catch((err) => {
        console.log(err);
        res.status(500).send({ status: "error", error: err });
      });
  } catch (error) {
    console.log(error);
  }
};

module.exports = getOneDonationDetails;
