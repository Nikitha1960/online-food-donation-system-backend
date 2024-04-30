const bcrypt = require('bcrypt');
const saltRounds = 10; // For hashing passwords
const { imageUpload } = require("../../common/imageUpload");

const Organization = require("../../models/organization.model");

// Register new organization
const createOrganization = async (req, res) => {
    const formData = req.body; // get data from the request body
    // console.log(formData);

    Organization.findOne({ email: formData.email })
        .then(async (organization) => {
            if (organization) {
                res.status(400).json({
                    message: "Organization already exists"
                })
            } else {
                const hashedPassword = bcrypt.hashSync(formData.password, saltRounds); // hash the password
                formData.password = hashedPassword; // set the hashed password to the formData object

                // upload the registration certificate
                formData.registrationCertificate = await imageUpload(formData.registrationCertificate);

                const newOrganization = new Organization(formData); // create a new organization
                newOrganization.save() // save the new organization to the database
                    .then(organization => {
                        res.status(201).json({
                            message: "Organization created successfully",
                            organization: organization
                        })
                    }).catch(err => {
                        res.status(500).json({
                            message: "Error creating organization",
                            error: err
                        })
                    })
            }
        }).catch(err => {
            res.status(500).json({
                message: "Error creating organization",
                error: err
            })
        })
}

// View all organizations 
const viewAllOrganizations = async (req, res) => {
    Organization
        .find()
        .then((organizations) => {
            res.json(organizations);
        })
        .catch((err) => {
            console.log(err.message);
            res.status(500).send({
                status: "Error with listing organizations",
            });
        });
}

module.exports = {
    createOrganization,
    viewAllOrganizations
}
