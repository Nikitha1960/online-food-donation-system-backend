const express = require("express");

const { createRequest } = require("../controllers/requester/CreateRequest");
const { requesterSignUp } = require("../controllers/requester/RequesterSignup");
const { viewUserProfile } = require("../controllers/requester/ViewProfile");
const { updateProfile, updatePassword } = require("../controllers/requester/UpdateProfile");
const { getAllRequests } = require("../controllers/request/allRequests");
const { getRequestersRequest } = require("../controllers/request/viewRequest");
const { getMyRequests } = require("../controllers/request/viewMyRequests");
const { deleteRequest } = require("../controllers/request/deleteRequest");


const router = express.Router();

router.post("/requesterSignUp", requesterSignUp);
router.post("/createRequest", createRequest);
router.get("/profile/:id", viewUserProfile);
router.put("/updateProfile/:id", updateProfile);
router.put("/updatePassword/:id", updatePassword);
router.get("/view/request/:id", getRequestersRequest);
router.get("/my/requests/:id", getMyRequests);
router.get("/allrequests", getAllRequests);
router.delete("/delete/:id" ,deleteRequest);

module.exports = router;
