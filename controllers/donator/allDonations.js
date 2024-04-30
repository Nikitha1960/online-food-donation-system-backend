const Donation = require("../../models/donation.model");

const getAllDonations = (req, res) => {
  try {
    Donation.find({
      status: "active",
    })
      .then((donations) => {
        res.json(donations);
      })
      .catch((err) => {
        res.status(500).send({
          msg: "Error fetching data",
          error: err,
        });
      });
    // Donation.aggregate([
    //   {
    //     $sample: { size: 3 },
    //   },
    // ])
    //   .then((donations) => {
    //     console.log(donations);
    //   })
    //   .catch((e) => {
    //     console.log(e);
    //   });
  } catch (error) {
    console.log(error);
  }
};

module.exports = {
  getAllDonations,
};
