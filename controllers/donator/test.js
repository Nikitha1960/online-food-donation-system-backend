const { imageUpload } = require("../../common/imageUpload");

const testBase64 = async (req, res) => {
  const base64 = req.body.base64;
  //   console.log(base64);
  const result = await imageUpload(base64);
  console.log(result);
};

module.exports = {
  testBase64,
};
