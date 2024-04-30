const { sendDonationDeletedEmail } = require("../../common/sendEmail");
const Donation = require("../../models/donation.model");
const DonationRequest = require("../../models/donationRequest.model");

const deleteDonation = async (req, res) => {
  try {
    var emailArray = [];
    var donationTitle = "";
    const donationID = req.params.id;
    console.log(donationID);
    await Donation.findById(donationID).then((donation) => {
      donationTitle = donation.donationTitle;
    });
    await DonationRequest.find({ donationID: donationID }).then((donation) => {
      // const emailArray = donation.numberOfRequests;

      for (let index = 0; index < donation.length; index++) {
        // console.log(index.requesterEmail);
        // console.log();
        var element = donation[index].requesterEmail;
        emailArray.push(element);
      }
      if (!emailArray.length == 0) {
        for (let index = 0; index < emailArray.length; index++) {
          const email = emailArray[index];
          sendDonationDeletedEmail(email, donationTitle);
        }
      }

      console.log(emailArray);
      // console.log(donation);
    });

    await Donation.findByIdAndDelete(donationID)
      .then(() => {
        console.log("sds");
        res.status(200).send({
          msg: "donation succesfully deleted",
        });
      })
      .catch((err) => {
        res.status(500).send({
          msg: "error with deletion",
          error: err,
        });
      });
  } catch (error) {
    console.log(error);
  }
};

module.exports = {
  deleteDonation,
};
