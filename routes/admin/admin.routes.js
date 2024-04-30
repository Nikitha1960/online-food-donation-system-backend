const express = require("express");
const verifyJWT = require("../../middleware/verifyJWT")


const {getRequestedOrganizations}=require("../../controllers/admin/requestedOrganization");
const {getApprovedOrganizations}=require("../../controllers/admin/approvedOrganization");
const {deleteReqOrganization}=require("../../controllers/admin/deleteReqOrg")
const {getOneOrganizationDetails}=require("../../controllers/admin/oneOrganizationiDetails");
const {getRequestedFunds}=require("../../controllers/admin/fundlist");
const{getApprovedFunds}=require("../../controllers/admin/fundlist");
const{editOrganization}=require("../../controllers/admin/updateOrg");
const{updateDonationStatus}=require("../../controllers/admin/updateDonationStatus");
const{getAllPendingDonations}=require("../../controllers/admin/pendingDonationList");
const { getAllUsers } = require("../../controllers/admin/getAllUsers");
const { getAllAcceptedDonations } = require("../../controllers/admin/acceptedDonationList");
const { editOrganizationStatus } = require("../../controllers/admin/updateOrgStatus");
const { updateFundStatus } = require("../../controllers/admin/updateFundStatus");
const { deleteDonationRequest } = require("../../controllers/admin/deleteDonationRequest");
const { rejectDonation } = require("../../controllers/admin/rejectDonation");

const router = express.Router();

router.get("/reqorglist",getRequestedOrganizations);
router.get("/approvedorg",getApprovedOrganizations);
router.get("/vieworg/:id",getOneOrganizationDetails);
router.get("/reqfunds",getRequestedFunds);
router.get("/approvedfunds",getApprovedFunds);
router.delete("/deletereqorg/:id",deleteReqOrganization);
router.put("/editorg/:id",editOrganization);
router.put("/uporgstatus/:id",editOrganizationStatus);
router.put("/upfundstatus/:id",updateFundStatus);
router.put("/updostauts/:id",updateDonationStatus);
router.get("/getpdon/", getAllPendingDonations);
router.get("/getaccepteddon/",getAllAcceptedDonations)
router.get("/getusers",getAllUsers);
router.delete("/deletedonreq/:id",deleteDonationRequest);
router.put("/rejectdonation/:id",rejectDonation);



module.exports = router;
