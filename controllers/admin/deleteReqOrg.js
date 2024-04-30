const Organization = require("../../models/organization.model");

const deleteReqOrganization = async (req, res) => {
  try {
    const id = req.params.id;
    console.log(id)

    await Organization.findByIdAndDelete(id)
      .then(() => {
        res.status(200).send({
          msg: "Requested Organization succesfully deleted",
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
  deleteReqOrganization,
};
