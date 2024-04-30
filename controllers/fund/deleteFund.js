const { sendOrganizationEmail } = require("../../common/sendEmail");
const Fund = require("../../models/fund.model");
const FundDonation = require("../../models/fundDonation.model");
const Requester = require("../../models/requester.model");

// Delete the fund details from database
const deleteFund = async (req, res) => {
    try {
        const fundID = req.params.id;

        await Fund.findByIdAndDelete(fundID)
            .then(() => {
                res.status(200).send({
                    msg: "Fund succesfully deleted.",
                });
            }).catch((err) => {
                res.status(500).send({
                    msg: "Error with removing the fund.",
                    error: err,
                });
            }
            );
    } catch (error) {
        console.log(error);
    }
}

// Mark the status of the fund as removed
const removeFund = async (req, res) => {
    try {
        const fundID = req.params.id;
        await Fund.findByIdAndUpdate(fundID, { status: "removed" })
            .then(async () => {
                try {
                    const fund = await Fund.findById(fundID, { title: 1 });
                    // FundDonation.find({ fundID: fundID }, { userID: 1 })
                    FundDonation.distinct("userID", { fundID: fundID })
                        .then((users) => {
                            users.forEach((user) => {
                                Requester.findById(user, { email: 1 })
                                    .then((requester) => {
                                        console.log("Sending email to " + requester.email);
                                        sendOrganizationEmail(
                                            requester.email,
                                            "Fund Removed - " + fund.title,
                                            "A fund you donated to has been removed by the organization. Donated amount will be refunded to your account. Contact the organization for more details. Thank you for your support."
                                        )
                                    })
                            })
                        })
                } catch (err) {
                    console.log(err);
                }
                res.status(200).send({
                    msg: "Fund succesfully removed.",
                });
            }).catch((err) => {
                res.status(500).send({
                    msg: "Error with removing the fund.",
                    error: err,
                });
            })
    } catch (error) {
        console.log(error);
    }
}

module.exports = {
    deleteFund,
    removeFund
};