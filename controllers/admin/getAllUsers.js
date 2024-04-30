
const User=require("../../models/requester.model")

const getAllUsers = (req, res) => {
    try {
        User.find()
            .then((organizations) => {
                res.json(organizations);
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
};

module.exports = {
    getAllUsers,
};