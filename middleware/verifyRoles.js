const jwt = require('jsonwebtoken');

const verifyRoles = (...allowedRoles) => {
    return (req, res, next) => {
        const authHeader = req.headers.authorization || req.headers.Authorization;
        if (!authHeader?.startsWith('Bearer ')) return res.sendStatus(401);
        const token = authHeader.split(' ')[1];

        jwt.verify(
            token,
            process.env.ACCESS_TOKEN_SECRET,
            (err, decoded) => {
                if (err) {
                    console.log(err);
                    return res.sendStatus(403)
                }
                var isValid = false
                const loggedRole = decoded.UserInfo.roles
                const rolesArray = [...allowedRoles];
                // console.log(rolesArray);
                rolesArray.map(role => {
                    if (role == loggedRole) {
                        isValid = true
                    }
                })
                if (isValid) {
                    next()
                } else {
                    return res.sendStatus(403)
                }

            }
        )
        // if (!req?.roles) return res.sendStatus(401);
        // const result = req.roles.map(role => rolesArray.includes(role)).find(val => val === true);
        // if (!result) return res.sendStatus(401);
        // next();
    }
}

module.exports = verifyRoles