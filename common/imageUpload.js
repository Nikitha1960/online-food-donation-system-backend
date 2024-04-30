const cloudinary = require("cloudinary").v2;
cloudinary.config({
  cloud_name: "dicjf8jjn",
  api_key: "153389117368677",
  api_secret: "iQGV8ggQU3UvZY9l2u7N4rpTYRM",
});

async function imageUpload(imageBase64) {
  try {
    const imageUploaded = await cloudinary.uploader.upload(
      imageBase64,
      {
        folder: "akila",
      },
      function (error, result) {
        console.log(result, error);
      }
    );
    //   console.log(imageUploaded);
    return imageUploaded.url;
  } catch (error) {
    console.log(error);
  }
}
module.exports = {
  imageUpload,
};
