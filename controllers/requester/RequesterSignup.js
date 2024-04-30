const bcrypt = require("bcrypt");
const saltRounds = 10; // For hashing passwords
const SignUp = require("../../models/requester.model");

const requesterSignUp = async (req, res) => {
  const userData = req.body; // get user data
  console.log(userData);

  await SignUp.findOne({ email: userData.email }).then(async (signup) => {
    if (signup) {
      res.status(400).json({
        message: "The user already exists",
      });
    } else {
      const hashedPassword = bcrypt.hashSync(userData.password, saltRounds); // hash the password
      userData.password = hashedPassword; // set the hashed password to the userData object

      //create new account
      const newRequester = new SignUp(userData);
      await newRequester
        .save()
        .then((SignUp) => {
          res.status(201).json({
            message: "User account created successfully",
            Signup: SignUp,
          });
        })
        .catch((err) => {
          res.status(500).json({
            message: "Error creating user account",
            error: err,
          });
        })
        .catch((err) => {
          res.status(500).json({
            message: "Error creating user account",
            error: err,
          });
        });
    }
  });
};

module.exports = { requesterSignUp };
