const express = require("express");

const{handleLogin,}=require('../controllers/authController');
const{createUser,}=require('../controllers/registerController')

const router=express.Router();

router.post("/login",handleLogin)
router.post("/register",createUser)

module.exports = router;
