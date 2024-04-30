const Donation = require("../../models/donation.model");
const Fund = require("../../models/fund.model");
const RequestFund = require("../../models/requestFund.model");

const getRandomDonations = async (req, res) => {
  // Get 3 random donations to view in the home page
  // To increase the random number edit the size int
  try {
    await Donation.aggregate([
      { $match: { status: "active" } },
      {
        $sample: { size: 4 },
      },
    ])
      .then((donations) => {
        res.json(donations);
      })
      .catch((e) => {
        res.json(e);
      });
  } catch (error) {
    console.log(error);
  }
};

const getRandomRequests = async (req, res) => {
  try {
    await RequestFund.aggregate([
      { $match: { status: "active" } },
      {
        $sample: { size: 3 },
      },
    ])
      .then((donations) => {
        res.json(donations);
      })
      .catch((e) => {
        res.json(e);
      });
  } catch (error) {
    console.log(error);
  }
};

const getRandomFunds = async (req, res) => {
  try {
    await Fund.aggregate([
      { $match: { status: "approved" } },
      {
        $sample: { size: 3 },
      },
    ])
      .then((donations) => {
        res.json(donations);
      })
      .catch((e) => {
        res.json(e);
      });
  } catch (error) {
    console.log(error);
  }
};

module.exports = {
  getRandomDonations,
  getRandomFunds,
};
