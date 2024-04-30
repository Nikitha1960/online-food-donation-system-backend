const Requester = require("../../models/requester.model");

const viewUserProfile = async (req, res) => {
    try {
      const userId = req.params.id;
      console.log(userId);
      await Requester.findOne({ _id: userId })
        .then((requester) => {
          res
            .status(200)
            .send({ message: "User fetched", requester: requester });
        })
        .catch((err) => {
          console.log(err);
          res.status(500).send({ status: "error", error: err });
        });
    } catch (error) {
      console.log(error);
    }
  };
  
  module.exports = { viewUserProfile };