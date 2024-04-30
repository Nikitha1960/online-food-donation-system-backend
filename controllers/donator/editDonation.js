const { imageUpload } = require("../../common/imageUpload");
const { body, validationResult } = require("express-validator");
const Donation = require("../../models/donation.model");

const editDonation = async (req, res) => {
  try {
    // const errors = validationResult(req);
    // console.log(errors);
    // if (!errors.isEmpty()) {
    //   res.status(422).json({ errors: errors.array() });
    //   return;
    // }
    const donationID = req.params.id;

    const { donationTitle, email, contactNumber, donationDescription } =
      req.body;

    const updateDonation = {
      donationTitle,
      email,
      contactNumber,
      donationDescription,
      status: "pending",
    };

    await Donation.findByIdAndUpdate(donationID, updateDonation)
      .then((donation) => {
        console.log(donation);
        res.status(200).send({ status: "donation updated" });
      })
      .catch(() => {
        res.status(500).send({ status: "error" });
      });
  } catch (error) {
    console.log(error);
  }
};

module.exports = {
  editDonation,
};
