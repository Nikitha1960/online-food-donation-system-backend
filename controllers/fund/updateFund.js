const { imageUpload } = require("../../common/imageUpload")
const { sendOrganizationEmail } = require("../../common/sendEmail")

const Fund = require("../../models/fund.model");
const User = require("../../models/user");

const updateFund = async (req, res) => {
    try {
        const formData = req.body;
        const fundId = req.params.id;
        const imageIsUpdated = formData.imageIsUpdated;

        // set fund status to pending
        formData.status = "pending";

        // if image is updated, upload image to cloudinary
        if (imageIsUpdated) {
            const imageBase64 = formData.fundImage;
            formData.fundImage = await imageUpload(imageBase64);
        }

        await Fund.findByIdAndUpdate(fundId, formData)
            .then(fund => {
                try {
                    User.findById(formData.organizationID, { email: 1 })
                        .then(user => {
                            // console.log(user.toObject().email);
                            sendOrganizationEmail(
                                user.toObject().email,
                                "Fund Update - " + formData.title,
                                "Your fund data has been submitted for review. You will be notified once it is approved."
                            )
                        })
                } catch (error) {
                    console.log(error);
                }
                res.status(201).json({
                    message: "Fund updated successfully",
                    fund: fund
                })
            }
            ).catch(err => {
                console.log(err.message);
                res.status(500).json({
                    message: "Error updating fund",
                    error: err
                })
            }
            )

    } catch (error) {
        console.log(error);
    }
}

module.exports = {
    updateFund
}
