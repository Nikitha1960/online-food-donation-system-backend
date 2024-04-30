const { imageUpload } = require("../../common/imageUpload")
const { sendEmail } = require("../../common/sendEmail")

const Fund = require("../../models/fund.model")

const updateFundStatus = async (req, res) => {
    try {
        const fundId = req.params.id;

        // set fund status to accepted
        const status = "approved";

        const updateFund={
            status
        }


        await Fund.findByIdAndUpdate(fundId, updateFund)
            .then(fund => {
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
    updateFundStatus
}
