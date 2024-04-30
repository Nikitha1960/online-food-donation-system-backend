const express = require("express");
const { donateToFund } = require("../controllers/donator/donateFund");
const { getAllFunds } = require("../controllers/fund/allFunds");

const { createFund } = require("../controllers/fund/createFund");
const { deleteFund, removeFund } = require("../controllers/fund/deleteFund");
const { getFund, getFundByStatus } = require("../controllers/fund/getFund");
const { getOrganizationFunds, getFundByOrganizationAndStatus, getNFunds } = require("../controllers/fund/getOrganizationFunds");
const { updateFund } = require("../controllers/fund/updateFund");

const router = express.Router();

router.get("/", getAllFunds);
router.get("/:organizationId/limit/:limit", getNFunds);
router.get("/:id", getFund);
router.post("/donateFund/:id", donateToFund);
router.post("/create", createFund);
router.put("/update/:id", updateFund);
router.delete("/delete/:id", deleteFund);
router.put("/remove/:id", removeFund);
router.get("/status/:status", getFundByStatus);
router.get("/:oranizationID/:fundID", getOrganizationFunds);
router.get("/:organizationID/status/:status", getFundByOrganizationAndStatus);

module.exports = router;