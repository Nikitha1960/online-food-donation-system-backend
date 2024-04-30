const DonationRequest = require("../../models/donation.model");

const deleteDonationRequest = async (req, res) => {
  try {
    const id = req.params.id;
    console.log(id)

    await DonationRequest.findByIdAndDelete(id)
      .then(() => {
        res.status(200).send({
          msg: "Requested Donation succesfully deleted",
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
  deleteDonationRequest,
};
