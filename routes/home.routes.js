const express = require("express");
const {
  getRandomDonations,
  getRandomFunds,
} = require("../controllers/home/homeController");

const router = express.Router();

router.get("/donations", getRandomDonations);
router.get("/funds", getRandomFunds);

module.exports = router;
