const { imageUpload } = require("../../common/imageUpload");

const Request = require("../../models/requestFund.model");

const UpdateRequest = async (req, res) => {
    try {
        const formData = req.body;
        const requestId = req.params.id;
        const imageIsUpdated = formData.imageIsUpdated;

        if (imageIsUpdated) {
            const imageBase64 = formData.requestImage;
            formData.requestImage = await imageUpload(imageBase64);
        }

        await Request.findByIdAndUpdate(requestId, formData)
        .then(request => {
            res.status(201).json({
                message: "Request updated successfully",
                request: request
            })
        }).catch(err => {
            console.log(err.message);
            res.status(500).json({
                message: "Error with updating request",
                error: err,
            })
        })
    } catch (error) {
        console.log(error);
    }
}

module.exports = {
    UpdateRequest
}