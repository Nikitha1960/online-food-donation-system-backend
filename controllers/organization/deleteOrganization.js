const Organization = require("../../models/organization.model");

const deleteOrganization = async (req, res) => {
    try {
        const organizationID = req.params.id;

        await Organization.findByIdAndDelete(organizationID)
            .then(() => {
                res.status(200).send({
                    msg: "Organization succesfully deleted.",
                });
            })
            .catch((err) => {
                res.status(500).send({
                    msg: "Error with removing the organnization.",
                    error: err,
                });
            });
    } catch (error) {
        console.log(error);
    }
}

module.exports = {
    deleteOrganization,
};