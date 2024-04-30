const { imageUpload } = require("../../common/imageUpload");
const { body, validationResult } = require("express-validator");
const Donation=require("../../models/donationRequest.model")

const rejectDonation = async (req, res) => {
  try {
    // const errors = validationResult(req);
    // console.log(errors);
    // if (!errors.isEmpty()) {
    //   res.status(422).json({ errors: errors.array() });
    //   return;
    // }
    const donationID = req.params.id;
    

    const  status  = "rejected"

    const updateDonation = {
      status
    };
    console.log(updateDonation)

    await Donation.findByIdAndUpdate(donationID, updateDonation)
      .then(() => {
        res.status(200).send({ message: "Status updated"  });
      })
      .catch(() => {
        res.status(500).send({ message: "Error"  });
      });
  } catch (error) {
    console.log(error);
  }
};

module.exports = {
  rejectDonation,
};
