const jwt = require("jsonwebtoken");

const verifyToken = (req, res, next) => {
    const authHeader = req.headers.token;
    if (authHeader) {
        const token = authHeader.split(" ")[1];
        jwt.verify(token, process.env.JWT_SEC, (err, user) => {
            if (err) {
                return res.status(403).json("Token is not valid!"); // Use return to stop execution
            }
            req.user = user;
            next(); // Continue to the next middleware or route handler
        });
    } else {
        return res.status(401).json("You are not authenticated"); // Use return to stop execution
    }
};

const verifyTokenAndAuthorization = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.id === req.params.id || req.user.isAdmin) {
            next(); // Continue to the next middleware or route handler
        } else {
            return res.status(403).json("You are not allowed to do that!"); // Use return to stop execution
        }
    });
};

const verifyTokenAndAdmin = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.isAdmin) {
            next();
        } else {
            res.status(403).json("You are not allowed to do that!");
        }
    });
};

module.exports = { 
    verifyToken, 
    verifyTokenAndAuthorization,
    verifyTokenAndAdmin,
 };
