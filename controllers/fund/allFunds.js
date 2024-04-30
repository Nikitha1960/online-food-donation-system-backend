const Fund = require("../../models/fund.model");

const getAllFunds = (req, res) => {
    try {
        Fund.find()
            .then((funds) => {
                res.json(funds);
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

module.exports = {
    getAllFunds,
};