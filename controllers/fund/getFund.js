const Fund = require("../../models/fund.model");

const getFund = (req, res) => {
    try {
        Fund.findById(req.params.id)
            .then((fund) => {
                res.status(200).send({
                    fund
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

// Get fund by status
const getFundByStatus = (req, res) => {
    try {
        Fund.find({ status: req.params.status })
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
    getFund, 
    getFundByStatus
};