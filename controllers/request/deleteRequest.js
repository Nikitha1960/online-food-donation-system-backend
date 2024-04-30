const Requests = require("../../models/requestFund.model");

const deleteRequest = async (req, res) => {
    try {
        const requestID = req.params.id;

        await Requests.findByIdAndDelete(requestID)
        .then(() => {
            res.status(200).send({
                msg: "Request deleted succesfully.",
            });
        }).catch((err) => {
            res.status(500).send({
                msg: "error with deleting the request",
                error: err,
            });
        });
    } catch (error) {
        console.log(error);
    }
}

module.exports = {
    deleteRequest,
};