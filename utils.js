const jwt = require("jsonwebtoken");

module.exports = {
    validateToken: (req, res, next) => {
        const authorizationHeader = req.headers.authorization;
        let result;
        if (authorizationHeader) {
            const token = req.headers.authorization.split(" ")[1]; // Bearer <token>
            const options = { expiresIn: "2d" };
            try {
                // `verify` makes sure that the token hasn't expired and has been issued by us
                result = jwt.verify(token, process.env.JWT_SECRET, options);
                req.decoded = result;
                next();
            } catch (err) {
                throw new Error(err);
            }
        } else {
            result = {
                error: "Authentication error. Token required.",
                status: 401
            };
            res.status(401).send(result);
        }
    }
}