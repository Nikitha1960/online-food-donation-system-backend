const Request = require("../../models/requestFund.model");

const getMyRequests = async (req, res) => {
    try {
        const userId = req.params.id;

        await Request.find({ userId: userId })
        .then((requests) => {
            res.status(200).send({
                requests
            });
        }).catch((err) => {
            res.status(500).send({
                msg: "error with fetching data",
                error: err,
            });
        });
    } catch (error) {
        console.log(error);
    }
    
}

module.exports = {
    getMyRequests,
}