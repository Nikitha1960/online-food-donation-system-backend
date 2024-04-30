const Organization = require("../../models/organization.model");

const getOrganization = (req, res) => {
    try {
        // console.log(req.params.id);
        Organization.findById(req.params.id)
        .then((organization) => {
                res.status(200).send({
                    organization
                });
            })
            .catch((err) => {
                res.status(500).send({
                    msg: "Error fetching data",
                    error: err,
                });
            });
    } catch (error) {
        console.log(error);
    }
};

module.exports = {
    getOrganization,
};
