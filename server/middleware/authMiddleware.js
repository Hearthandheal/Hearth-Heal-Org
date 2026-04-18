import jwt from "jsonwebtoken";

export const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) return res.status(401).json("No token provided");

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json("Invalid token");
  }
};

export const verifyAdmin = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) return res.status(401).json("No token");

  const decoded = jwt.verify(token, process.env.JWT_SECRET);

  if (!decoded.isAdmin) return res.status(403).json("Not admin");

  req.user = decoded;
  next();
};
