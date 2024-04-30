const { body, validationResult } = require("express-validator");

exports.validate = (method) => {
  switch (method) {
    case "createDonation": {
      return [
        body("donationTitle", "Title does not exist").exists(),
        body("contactNumber", "Contact number does not exist or invalid")
          .exists()
          .isInt()
          .isLength({ min: 10, max: 10 }),
        body("email", "Email does not exist or invalid").exists().isEmail(),
        body("donationDescription", "Description does not exist").exists(),
      ];
    }
  }
};
