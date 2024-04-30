const Requests = require("../../models/requestFund.model");

const getAllRequests = (req, res) => {
    try {
        Requests.find()
        .then((requests) => {
            res.json(requests);
        }).catch((err) => {
            res.status(500).send({
                msg: "Error with fetching data",
                error: err,
            });
        });
    } catch (error) {
        console.log(error);
    }
}

module.exports = {
    getAllRequests,
};