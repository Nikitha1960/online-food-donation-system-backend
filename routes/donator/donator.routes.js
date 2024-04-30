const express = require("express");
const { getAllDonations } = require("../../controllers/donator/allDonations");
const { createDonation } = require("../../controllers/donator/createDonation");
const { deleteDonation } = require("../../controllers/donator/deleteDonation");
const { donateToFund } = require("../../controllers/donator/donateFund");
const { editDonation } = require("../../controllers/donator/editDonation");
const {
  getCompletedDonations,
  getOngoingDonations,
  getPendingDonations,
  getRejectedDonations,
  getUserDonations,
} = require("../../controllers/donator/getDonations");
const getOneDonationDetails = require("../../controllers/donator/getOneDonation");
const {
  getPendingRequests,
  getApprovedRequests,
} = require("../../controllers/donator/getRequests");
const {
  markDonationAsCompleted,
} = require("../../controllers/donator/markAsCompleted");

const {
  sendDonationRequest,
} = require("../../controllers/donator/sendDonationRequest");
const { testBase64 } = require("../../controllers/donator/test");
const {
  acceptDonationRequest,
  rejectDonationRequest,
} = require("../../controllers/donator/updateRequestStatus");
const { validate } = require("../../middleware/donationValidation");

const router = express.Router();

router.post("/createDonation", validate("createDonation"), createDonation);
router.get("/getDonations", getAllDonations);
router.delete("/deleteDonation/:id", deleteDonation);
router.get("/getCompletedDonations/:id", getCompletedDonations);
router.get("/getOngoingDonations/:id", getOngoingDonations);
router.get("/getPendingDonations/:id", getPendingDonations);
router.get("/getRejectedDonations/:id", getRejectedDonations);
router.get("/getOneDonation/:id", getOneDonationDetails);
router.put("/updateDonation/:id", editDonation);
router.post("/sendRequest", sendDonationRequest);
router.post("/donateFund/:id", donateToFund);

router.get("/getPendingRequests/:id", getPendingRequests);
router.put("/acceptRequest/:id", acceptDonationRequest);
router.put("/rejectRequest/:id", rejectDonationRequest);
router.put("/markAsCompleted/:id", markDonationAsCompleted);
router.get("/getApprovedRequests/:id", getApprovedRequests);
router.get("/getUserDonations/:id", getUserDonations);

router.post("/test", testBase64);

module.exports = router;
