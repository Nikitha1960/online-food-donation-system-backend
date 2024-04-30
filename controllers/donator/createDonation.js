const { imageUpload } = require("../../common/imageUpload");
const { sendEmail } = require("../../common/sendEmail");
const { body, validationResult } = require("express-validator");
const Donation = require("../../models/donation.model");

const createDonation = async (req, res) => {
  try {
    var donationImage;
    const errors = validationResult(req);
    console.log(errors);
    if (!errors.isEmpty()) {
      res.status(422).json({ errors: errors.array() });
      return;
    }
    // const emailArray = [
    //   "akilakavinda909@gmail.com",
    //   "akilakavinda909@gmail.com",
    //   "akilakavinda909@gmail.com",
    //   "akilakavinda909@gmail.com",
    // ];
    const donationData = req.body;
    // console.log(donationData.donationImage);
    if (donationData.donationImage != null) {
      const imageBase64 = donationData.donationImage;
      donationImage = await imageUpload(imageBase64);
    }
    // const imageBase64 = donationData.donationImage;
    // const donationImage = await imageUpload(imageBase64);

    // var imageUploaded = await imageUpload(imageBase64);
    // console.log(imageUploaded);
    const {
      userID,
      donationTitle,
      email,
      location,
      contactNumber,
      donationDescription,
      donationEndDate,
    } = req.body;
    const newDonation = new Donation({
      userID,
      donationTitle,
      email,
      location,
      donationEndDate,
      contactNumber,
      donationImage: donationImage,
      donationDescription,
    });

    newDonation
      .save()
      .then((donation) => {
        // for (let index = 0; index < emailArray.length; index++) {
        //   sendEmail(emailArray[index], "loopTEst");
        // }
        sendEmail(email, donationTitle);
        console.log(donation);
        res.status(201).json({
          message: "Donation created successfully",
          donation: donation,
        });
      })
      .catch((err) => {
        res.status(500).json({
          message: "Error creating donation",
          error: err,
        });
      });
  } catch (error) {
    console.log(error);
  }
};

module.exports = {
  createDonation,
};