const Request = require("../../models/requestFund.model");

const getRequestersRequest = async (req, res) => {
    try {
        const requesterId = req.params.id;

        await Request.find({ _id: requesterId })
        .then((requests) => {
            res.status(200).send({
                requests
            });
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
    getRequestersRequest,
}