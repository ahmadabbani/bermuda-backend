import jwt from "jsonwebtoken";
import "dotenv/config";

const authenticateUser = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ error: "Unauthorized: No token found." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    // Hardcoded secret
    console.log("token:", decoded);
    req.user = {
      id: decoded.id.toString(),
      role: decoded.role,
      authorized: decoded.authorized,
    };
    next();
  } catch (error) {
    console.error("Token verification failed:", error);
    res.status(401).json({ error: "Invalid token." });
  }
};

export default authenticateUser;
