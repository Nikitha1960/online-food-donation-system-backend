const User = require('../models/user');
const Organization = require('../models/organization.model');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Requester = require('../models/requester.model');

const handleLogin = async (req, res) => {
    console.log("PASSEDDD")
    const { username, password, email } = req.body;
    let foundUser;

    if ((!username || !email) && !password) return res.status(400).json({ 'message': 'Username and password are required.' });

    foundUser = await Requester.findOne({ email: username }).exec();
    console.log("Found user after Requester query:", foundUser);
    if (!foundUser) {
        foundUser = await Organization.findOne({ email: username }).exec();
        console.log("Found user after Organization query:", foundUser);
    } else if (!foundUser) {
        return res.sendStatus(401); // Unauthorized 
    }

    if (!foundUser) {
        return res.sendStatus(401); // Unauthorized 
    }

    console.log(foundUser);

    const match = await bcrypt.compare(password, foundUser.password);

    console.log(foundUser);
    const match1 = await bcrypt.compare(password, foundUser.password);

    console.log(password);
    console.log(foundUser.password);
    console.log(match);

    if (match) {
        const roles = foundUser.roles;
        const _id = foundUser._id;

        console.log("PASSED1");
        // create JWTs
        const accessToken = jwt.sign(
            {
                "UserInfo": {
                    "username": foundUser.username,
                    "roles": roles,
                    "_id": _id
                }
            },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '1h' }
        );
        const refreshToken = jwt.sign(
            { "username": foundUser.username },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: '1d' }
        );
        // Saving refreshToken with current user
        foundUser.refreshToken = refreshToken;
        const result = await foundUser.save();
        console.log(result);
        console.log(roles);
        console.log(_id);

        // Creates Secure Cookie with refresh token
        res.cookie('jwt', refreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });

        // Send authorization roles and access token to user
        res.json({ roles, accessToken, _id });
        console.log(accessToken);
    } else {
        res.seStatus(401);
    }
}

module.exports = { handleLogin };
