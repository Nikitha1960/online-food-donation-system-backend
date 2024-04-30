const bcrypt = require('bcrypt');
const saltRounds = 10; // For hashing passwords

const { sendEmail } = require("../../common/sendEmail");

const Organization = require("../../models/organization.model");

const updateOrganization = async (req, res) => {
    const formData = req.body;
    const organizationId = req.params.id;

    Organization.findOne({ email: formData.email })
        .then(async (organization) => {
            // if organization is available with the email 
            // and the id is not the same as the id of the organization being updated
            if (organization && organization._id != organizationId) {
                res.status(400).json({
                    message: "Organization already exists"
                })
            } else {
                try {
                    await Organization.findByIdAndUpdate(organizationId, formData)
                        .then(organization => {
                            res.status(201).json({
                                message: "Organization updated successfully",
                                organization: organization
                            })
                        }
                        ).catch(err => {
                            console.log(err.message);
                            res.status(500).json({
                                message: "Error updating organization",
                                error: err
                            })
                        }
                        )

                } catch (error) {
                    console.log(error);
                }
            }
        })
}

// Update board member details
const updateOrganizationBoard = async (req, res) => {
    const formData = req.body;
    const organizationId = req.params.id;

    try {
        await Organization.findByIdAndUpdate(organizationId, formData)
            .then(organization => {
                res.status(201).json({
                    message: "Organization updated successfully",
                    organization: organization
                })
            }
            ).catch(err => {
                console.log(err.message);
                res.status(500).json({
                    message: "Error updating organization",
                    error: err
                })
            }
            )

    } catch (error) {
        console.log(error);
    }

}

// Change password
const changePassword = async (req, res) => {
    const formData = req.body;
    const organizationId = req.params.id;

    // console.log(formData, organizationId);

    const hashedPassword = bcrypt.hashSync(formData.password, saltRounds); // hash the password
    formData.password = hashedPassword; // set the hashed password to the formData object

    await Organization.findByIdAndUpdate(organizationId, formData)
        .then(organization => {
            res.status(201).json({
                message: "Password changed successfully",
                organization: organization
            })
        }).catch(err => {
            console.log(err.message);
            res.status(500).json({
                message: "Error changing password",
                error: err
            })
        })
}


module.exports = {
    updateOrganization,
    changePassword,
    updateOrganizationBoard
}