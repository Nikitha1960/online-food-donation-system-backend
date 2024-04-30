const FundDonation = require("../../../models/fundDonation.model");
const Requester = require("../../../models/requester.model");
const User = require("../../../models/user");

// Get latest n contributions
const getNContributions = async (req, res) => {
    const { limit, organizationID } = req.params;
    const result = []

    try {
        await FundDonation.find({
            organizationID: organizationID
        }).sort({ _id: -1 }).limit(limit)
            .then(async (contributions) => {
                for (const contribution of contributions) {
                    await Requester.findById(contribution.userID)
                        .then(async (user) => {
                            // add user name to contribution
                            if (user.firstName && user.lastName) {
                                contribution.userID = user.firstName + ' ' + user.lastName
                                result.push(contribution)
                            }
                            // console.log(result);
                        }).catch(err => {
                            // console.log("Error 01 " + err.message);
                            res.status(500).send({
                                msg: "Error fetching data",
                                error: err,
                            });
                        })
                }
                res.status(200).send({
                    contributions: result
                })
            }).catch((err) => {
                // console.log("Error 02 " + err.message);
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
    getNContributions
};