const Donation = require("../../models/donation.model");

const getCompletedDonations = async (req, res) => {
  await Donation.find({ status: "completed", userID: req.params.id })
    .then((donations) => {
      res.json(donations);
    })
    .catch((err) => {
      res.json({
        errror: err,
      });
    });
};

const getOngoingDonations = async (req, res) => {
  await Donation.find({ status: "active", userID: req.params.id })
    .then((donations) => {
      res.json(donations);
    })
    .catch((err) => {
      res.json({
        errror: err,
      });
    });
};

const getPendingDonations = async (req, res) => {
  await Donation.find({ status: "pending", userID: req.params.id })
    .then((donations) => {
      res.json(donations);
    })
    .catch((err) => {
      res.json({
        errror: err,
      });
    });
};

const getRejectedDonations = async (req, res) => {
  await Donation.find({ status: "rejected", userID: req.params.id })
    .then((donations) => {
      res.json(donations);
    })
    .catch((err) => {
      res.json({
        errror: err,
      });
    });
};

const getUserDonations = async (req, res) => {
  await Donation.find({ userID: req.params.id })
    .then((donations) => {
      res.json(donations);
    })
    .catch((err) => {
      res.json({
        errror: err,
      });
    });
};

module.exports = {
  getCompletedDonations,
  getOngoingDonations,
  getPendingDonations,
  getRejectedDonations,
  getUserDonations,
};
