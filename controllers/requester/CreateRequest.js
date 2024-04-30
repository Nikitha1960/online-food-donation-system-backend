const Request = require("../../models/requestFund.model");
const { imageUpload } = require("../../common/imageUpload");

const createRequest = async (req, res) => {
    const formData = req.body;
    console.log(formData)

    formData.requestImage = await imageUpload(formData.requestImage);

    const newRequest = new Request(formData); 
            newRequest.save() 
                    .then(request => {
                        res.status(201).json({
                            message: "Request created successfully",
                            request: request
                        })
                    }).catch(err => {
                        res.status(500).json({
                            message: "Error creating request",
                            error: err
                        })
                    })
            }
        
module.exports = { createRequest };