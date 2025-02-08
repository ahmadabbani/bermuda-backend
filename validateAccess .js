import jwt from "jsonwebtoken";

const validateAccess = (req, res, next) => {
  try {
    // Get token from cookies
    const token = req.cookies.token;

    if (!token) {
      return res.status(401).json({
        success: false,
        error: "No authentication token provided",
      });
    }

    // Verify and decode the token
    const decodedToken = jwt.verify(token, "jwt_secret_key");

    // Get the requested user ID from request body
    const { id } = req.params;
    console.log("valdateaccess id from params:", id);

    if (!id) {
      return res.status(400).json({
        success: false,
        error: "User ID is required",
      });
    }

    // Check if user has permission to access this profile
    // Allow access if user is requesting their own profile OR if they're an admin
    if (
      decodedToken.id.toString() !== id.toString() &&
      decodedToken.role !== "admin"
    ) {
      return res.status(403).json({
        success: false,
        error:
          "Access denied. You can only access your own profile unless you're an admin",
      });
    }

    // Add decoded user info to request for use in route handlers
    req.user = decodedToken;

    next();
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({
        success: false,
        error: "Invalid token",
      });
    }

    return res.status(500).json({
      success: false,
      error: "Internal server error during authentication",
    });
  }
};

export default validateAccess;
