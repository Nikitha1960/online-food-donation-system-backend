const Organization = require("../../models/organization.model");

const getOneOrganizationDetails = async (req, res) => {
  try {
    const id = req.params.id;
    console.log(id);
    await Organization.findOne({ _id: id})
      .then((org) => {
        res
          .status(200)
          .send({ message: "Organization fetched", org: org });
      })
      .catch((err) => {
        console.log(err);
        res.status(500).send({ status: "error", error: err });
      });
  } catch (error) {
    console.log(error);
  }
};

module.exports = {getOneOrganizationDetails,};
