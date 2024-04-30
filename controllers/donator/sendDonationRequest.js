const Donation = require("../../models/donation.model");
const DonationRequest = require("../../models/donationRequest.model");

const sendDonationRequest = async (req, res) => {
  var numberOfRequests = 0;
  try {
    const {
      donationID,
      requesterName,
      requesterEmail,
      requesterContact,
      requestDescription,
    } = req.body;

    const newRequest = new DonationRequest({
      donationID,
      requesterName,
      requesterEmail,
      requesterContact,
      requestDescription,
    });
    await newRequest
      .save()
      .then(async (request) => {
        console.log(request);
        //get the donation to which request is associated
        await Donation.findOne({ _id: donationID })
          .then(async (donation) => {
            console.log(donation);
            //increment number of requests
            numberOfRequests = donation.numberOfRequests;
            numberOfRequests++;
            const updateDonation = {
              numberOfRequests,
            };
            await Donation.findByIdAndUpdate(donationID, updateDonation)
              .then(() => {
                res.status(201).json({
                  message: "Requetsted created successfully",
                });
              })
              .catch((errorr) => {
                console.log(errorr);
              });
          })
          .catch((err) => {
            console.log(err);
          });
      })
      .catch((err) => {
        console.log(err);
      });
  } catch (error) {}
};

module.exports = {
  sendDonationRequest,
};
