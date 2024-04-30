const DonationRequest = require("../../models/donationRequest.model");

// const getRequests = async (req, res) => {
//   console.log(req.params.id);

//   await DonationRequest.find({
//     donationID: req.params.id,
//     requestStatus: "pending",
//   })
//     .then((requests) => {
//       res.json(requests);
//     })
//     .catch((err) => {
//       res.json({
//         error: err,
//       });
//     });
// };

const getPendingRequests = async (req, res) => {
  await DonationRequest.find({
    donationID: req.params.id,
    requestStatus: "pending",
  })
    .then((requests) => {
      res.json(requests);
    })
    .catch((err) => {
      res.json(err);
    });
};

const getRejectedRequests = async (req, res) => {
  console.log(req.params.id);
  try {
    await DonationRequest.find({
      donationID: req.params.id,
      requestStatus: "rejected",
    })
      .then((requests) => {
        res.json(requests);
      })
      .catch((err) => {
        res.json({
          error: err,
        });
      });
  } catch (error) {
    console.log(error);
  }
};

const getApprovedRequests = async (req, res) => {
  console.log(req.params.id);
  try {
    await DonationRequest.find({
      donationID: req.params.id,
      requestStatus: "accepted",
    })
      .then((requests) => {
        res.json(requests);
      })
      .catch((err) => {
        res.json({
          error: err,
        });
      });
  } catch (error) {
    console.log(error);
  }
};

module.exports = {
  getPendingRequests,
  getRejectedRequests,
  getApprovedRequests,
};
