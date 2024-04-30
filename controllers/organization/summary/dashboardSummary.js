const FundDonation = require("../../../models/fundDonation.model");
const User = require("../../../models/user");
const Fund = require("../../../models/fund.model");

const getDashboardSummary = async (req, res) => {
    const { organizationID } = req.params;
    const result = {
        totalDonations: 0,
        totalDonors: 0,
        totalFunds: 0,
        activeFunds: 0,
        totalFundsAmount: 0,
    }

    try {
        await FundDonation.find({
            organizationID: organizationID
        }).then(async (contributions) => {
            // get total donations received
            result.totalDonations = contributions.length;

            // get the number of donors
            const donors = new Set();
            for (const contribution of contributions) {
                donors.add(contribution.userID);
            }
            result.totalDonors = donors.size;

        }).catch((err) => {
            res.status(500).send({
                msg: "Error fetching data",
                error: err,
            });
        });

        await Fund.find({
            organizationID: organizationID
        }).then(async (funds) => {
            result.totalFunds = funds.length;
            for (const fund of funds) {
                if (fund.status === "approved") {
                    result.activeFunds++
                }
                result.totalFundsAmount += fund.currentAmount;
            }
            res.status(200).send({
                summary: result
            })
        }).catch((err) => {
            res.status(500).send({
                msg: "Error fetching data",
                error: err,
            });
        });
    } catch (error) {
        console.log(error);
    }
}

module.exports = {
    getDashboardSummary
};