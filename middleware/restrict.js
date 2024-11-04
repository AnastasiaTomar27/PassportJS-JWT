exports.restrict = (role) => {
    return (req, res, next) => {
        if(!req.user || req.user.role !== role) {
            return res.status(403).json({ errors: [{msg: "Access denied. You do not have the required permissions to access this resource."}] });
        } else {
            next();
        }
    }
}