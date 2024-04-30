const Fund = require("../../models/fund.model");

const getOrganizationFunds = async (req, res) => {
    try {
        const organizationID = req.params.id;

        await Fund.find({ organizationID: organizationID })
            .then((funds) => {
                res.status(200).send({
                    funds
                });
            }).catch((err) => {
                res.status(500).send({
                    msg: "Error fetching data",
                    error: err,
                });
            }
            );
    } catch (error) {
        console.log(error);
    }
}

// Get fund by organization and status
const getFundByOrganizationAndStatus = (req, res) => {
    try {
        // console.log(req.params);
        Fund.find({
            organizationID: req.params.organizationID,
            status: req.params.status
        })
            .then((funds) => {
                // console.log(funds);
                res.status(200).send({
                    funds
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
}

// Get latest n funds
const getNFunds = (req, res) => {
    const { limit } = req.params;

    try {
        Fund.find({
            status: { $in: ["approved", "completed"] },
            organizationID: req.params.organizationId
        }).sort({ _id: -1 }).limit(limit)
            .then((funds) => {
                res.status(200).send({
                    funds
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
}

module.exports = {
    getOrganizationFunds,
    getFundByOrganizationAndStatus,
    getNFunds
};