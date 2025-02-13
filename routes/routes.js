import express from "express";
import db from "../db.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken"; // For token creation
import crypto from "crypto"; // For generating unique tokens
import nodemailer from "nodemailer"; // For sending emails
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import { uploadToCloudinary } from "../utils/cloudinary.js";
import path from "path";
import "dotenv/config";
import validateAccess from "../validateAccess .js";
import authenticateUser from "../authenticateUser .js";

const router = express.Router();

const upload = multer({ storage: multer.memoryStorage() });
// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Sign-Up Route
router.post("/signup", async (req, res) => {
  const { username, email, phone, password } = req.body;

  // Email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({
      signupStatus: false,
      error: "Please enter a valid email address",
    });
  }

  try {
    // Check if user with the same email already exists
    const [existingUser] = await db.execute(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );
    if (existingUser.length > 0) {
      return res.status(400).json({
        signupStatus: false,
        error: "This email is already registered. Please use a different email",
      });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the user into the database
    await db.execute(
      "INSERT INTO users (username, email, phone, password, role) VALUES (?, ?, ?, ?, ?)",
      [username, email, phone, hashedPassword, "user"]
    );

    return res.status(200).json({
      signupStatus: true,
      message: "Registration successful! You can now sign in",
    });
  } catch (error) {
    console.error("Database query error:", error);
    return res.status(500).json({
      signupStatus: false,
      error:
        "Unable to complete registration at this time. Please try again later",
    });
  }
});

// Sign-In Route
router.post("/signin", async (req, res) => {
  const { email, password } = req.body;

  // Validate input
  if (!email && !password) {
    return res.status(400).json({
      signInStatus: false,
      error: "Please enter both email and password",
    });
  }
  if (!email) {
    return res.status(400).json({
      signInStatus: false,
      error: "Please enter your email",
    });
  }
  if (!password) {
    return res.status(400).json({
      signInStatus: false,
      error: "Please enter your password",
    });
  }

  // Email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({
      signInStatus: false,
      error: "Invalid email format",
    });
  }

  try {
    // Check if the user exists in the database
    const [user] = await db
      .execute("SELECT * FROM users WHERE email = ?", [email])
      .catch((err) => {
        console.error("Database query error:", err);
        throw new Error("Database query failed");
      });

    if (!user || user.length === 0) {
      return res.status(401).json({
        signInStatus: false,
        error: "Invalid email or password",
      });
    }

    const existingUser = user[0];
    //console.log("User found:", existingUser); // Add before bcrypt compare
    // Compare the provided password with the hashed password in the database
    const isPasswordValid = await bcrypt.compare(
      password,
      existingUser.password
    );

    if (!isPasswordValid) {
      return res.status(401).json({
        signInStatus: false,
        error: "Invalid email or password",
      });
    }

    // Determine the role from the database
    const role = existingUser.role;

    // Generate a JWT token
    const token = jwt.sign(
      {
        role,
        email: existingUser.email,
        id: existingUser.id,
        username: existingUser.username,
        phone: existingUser.phone,
        authorized: true,
      },
      process.env.JWT_SECRET_KEY,
      { expiresIn: "1d" }
    );

    // Set the token in a secure cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      partitioned: true,
      maxAge: 24 * 60 * 60 * 1000, // Optional: 1 day expiration
      path: "/",
    });
    // Then set Chrome-specific header
    res.setHeader("Supports-Loading-Mode", "credentialed-prerender");

    // Send response
    return res.status(200).json({
      signInStatus: true,
      token,
    });
  } catch (error) {
    console.error("Error during sign-in:", error);
    return res.status(500).json({
      signInStatus: false,
      error: "Unable to sign in at this time. Please try again later.",
    });
  }
});

// Route to request password reset
router.post("/reset-password-request", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.json({ status: false, error: "Email is required" });
  }

  try {
    // Check if the user exists
    const [user] = await db.execute("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (user.length === 0) {
      return res.json({ status: false, error: "User not found" });
    }

    const existingUser = user[0];

    // Generate a reset token and expiration time
    const resetToken = crypto.randomBytes(32).toString("hex");
    const tokenExpiration = new Date(Date.now() + 3600000); // 1 hour
    const formattedExpirationDate = tokenExpiration
      .toISOString()
      .slice(0, 19)
      .replace("T", " ");

    // Save the token in the database
    await db.execute(
      "UPDATE users SET reset_token = ?, token_expiration = ? WHERE id = ?",
      [resetToken, formattedExpirationDate, existingUser.id]
    );

    // Send the reset link via email
    const transporter = nodemailer.createTransport({
      service: "Gmail", // Or your email provider
      auth: {
        user: process.env.EMAIL_PROVIDER,
        pass: process.env.EMAIL_PASSWORD,
      },
      tls: {
        rejectUnauthorized: false, // Ignore SSL certificate errors
      },
    });

    const resetLink = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;
    const mailOptions = {
      from: process.env.EMAIL_PROVIDER,
      to: email,
      subject: "Password Reset Request",
      text: `Click the link to reset your password: ${resetLink}`,
    };

    await transporter.sendMail(mailOptions);

    return res.json({ status: true, message: "Reset link sent to email" });
  } catch (error) {
    console.error("Error during password reset request:", error);
    return res.json({ status: false, error: "Database query error" });
  }
});

// Route to reset the password
router.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  if (!newPassword) {
    return res.json({ status: false, error: "New password is required" });
  }

  try {
    const currentDate = new Date().toISOString().slice(0, 19).replace("T", " ");

    // Validate the token
    const [user] = await db.execute(
      "SELECT * FROM users WHERE reset_token = ? AND token_expiration > ?",
      [token, currentDate]
    );

    if (user.length === 0) {
      return res.json({ status: false, error: "Invalid or Expired Token" });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password and clear the token
    const [result] = await db.execute(
      "UPDATE users SET password = ?, reset_token = NULL, token_expiration = NULL WHERE id = ?",
      [hashedPassword, user[0].id]
    );

    // Clear the token
    res.clearCookie("token", {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      partitioned: true,
      path: "/",
    });

    return res.json({ status: true, message: "Password reset successful!" });
  } catch (error) {
    console.error("Error during password reset:", error);
    return res.json({ status: false, error: "Database query error" });
  }
});

// Route to log out
router.post("/logout", (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      partitioned: true,
      maxAge: 24 * 60 * 60 * 1000, // Optional: 1 day expiration
      path: "/",
    });
    // Then set Chrome-specific header
    res.setHeader("Supports-Loading-Mode", "credentialed-prerender");

    res.status(200).json({
      success: true,
      message: "You have been successfully logged out.",
    });
  } catch (err) {
    console.error("Error during logout:", err);
    res.status(500).json({ success: false, message: "Internal server error." });
  }
});

// Middleware to authenticate admin
/*const authenticateAdmin = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, "jwt_secret_key");
    if (decoded.role !== "admin") {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  } catch (error) {
    return res.status(401).json({ error: "Unauthorized" });
  }
};*/

// Protected route to create new admin
router.post("/create-admin", async (req, res) => {
  const { email, password, phone, username } = req.body;

  if (!email || !password || !username) {
    return res.status(400).json({
      success: false,
      error: "email, username and password are required",
    });
  }

  // Email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({
      success: false,
      error: "Invalid email format",
    });
  }

  try {
    // Check if email already exists
    const [existingUsers] = await db.execute(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );

    if (existingUsers.length > 0) {
      return res.status(409).json({
        success: false,
        error: "Email already exists",
      });
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    await db.execute(
      "INSERT INTO users (email, password, phone, username, role) VALUES (?, ?, ?, ?, 'admin')",
      [email, hashedPassword, phone, username]
    );

    return res.status(201).json({
      success: true,
      message: "Admin created successfully",
    });
  } catch (error) {
    console.error("Error creating admin:", {
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    return res.status(500).json({
      success: false,
      error: "Failed to create admin. Please try again.",
    });
  }
});

// route to place an order
router.post("/orders", async (req, res) => {
  const {
    product_name,
    total_price,
    quantity,
    type,
    email,
    //phone,
    username,
    user_id,
    // accountemail,
    status,
  } = req.body;
  // Handle missing or empty params
  const params = req.body.params ? String(req.body.params) : "";

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({
      orderStatus: false,
      error: "Please enter a valid email format.",
    });
  }

  /*if (email !== accountemail) {
    return res.status(400).json({
      orderStatus: false,
      error: "The email entered does not match your account email.",
    });
  }*/

  // Validate phone
  /*if (!phone) {
    return res.status(400).json({
      orderStatus: false,
      error: "Phone number is required.",
    });
  }*/

  let connection;
  try {
    // Get a connection from the pool
    connection = await db.getConnection();
    await connection.beginTransaction();

    // Insert the order into the orders table
    const [orderResult] = await connection.execute(
      "INSERT INTO orders (product_name, total_price, quantity, type, email, username, user_id, status, params) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [
        product_name,
        total_price,
        quantity,
        type,
        email,
        username,
        user_id,
        status,
        params,
      ]
    );

    // Get the inserted order's ID
    const order_id = orderResult.insertId;

    // Insert the transaction into the transactions table
    await connection.execute(
      "INSERT INTO transactions (amount, product_name, type, user_id, status, order_id) VALUES (?, ?, ?, ?, ?, ?)",
      [total_price, product_name, type, user_id, status, order_id]
    );

    // Commit the transaction
    await connection.commit();

    res.status(201).json({
      orderStatus: true,
      message: "Order placed successfully!",
    });
  } catch (error) {
    if (connection) await connection.rollback(); // Rollback transaction on error
    console.error("Error placing order:", error);
    res.status(500).json({
      orderStatus: false,
      error: "Failed to place the order. Please try again later.",
    });
  } finally {
    if (connection) connection.release(); // Release the connection
  }
});

// All orders Route
router.get("/orders", async (req, res) => {
  try {
    // Query to fetch all orders
    const [rows] = await db.execute(`
      SELECT *
      FROM orders
      ORDER BY created_at DESC
    `);

    // Convert total_price to a number
    const orders = rows.map((row) => ({
      ...row,
      total_price: parseFloat(row.total_price),
    }));

    // Send the orders data as JSON
    res.status(200).json(orders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Failed to fetch orders." });
  }
});

//Nb of users Route
router.get("/users/count", async (req, res) => {
  try {
    const [rows] = await db.execute(`
      SELECT COUNT(*) AS count
      FROM users
    `);
    res.status(200).json({ count: rows[0].count });
  } catch (error) {
    console.error("Error fetching total users:", error);
    res.status(500).json({ error: "Failed to fetch total users." });
  }
});

//fetch all users
router.get("/users", async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    // First, get total count of users
    const [countResult] = await db.execute(
      "SELECT COUNT(*) as total FROM users"
    );
    const totalUsers = countResult[0].total;
    const totalPages = Math.ceil(totalUsers / limit);

    // Then, get paginated users
    const [users] = await db.execute(
      `
      SELECT * FROM users
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `,
      [limit, offset]
    );

    res.status(200).json({
      users,
      totalPages,
      currentPage: page,
    });
  } catch (error) {
    console.error("Error fetching total users:", error);
    res.status(500).json({ error: "Failed to fetch total users." });
  }
});

// Search users route
router.get("/users/search", async (req, res) => {
  const { query } = req.query;

  if (!query) {
    return res.status(400).json({ error: "Search query is required." });
  }

  try {
    // SQL query to search users
    const searchQuery = `
      SELECT * FROM users 
      WHERE username LIKE ? OR email LIKE ? OR phone LIKE ?
      ORDER BY 
        CASE 
          WHEN username = ? THEN 1
          WHEN username LIKE ? THEN 2
          ELSE 3
        END
    `;

    // Prepare search patterns
    const exactMatch = query;
    const startsWith = `${query}%`;
    const contains = `%${query}%`;

    const [users] = await db.execute(searchQuery, [
      contains,
      contains,
      contains,
      exactMatch,
      startsWith,
    ]);

    res.status(200).json(users);
  } catch (error) {
    console.error("Error searching users:", error);
    res.status(500).json({ error: "Failed to search users." });
  }
});

// Delete user
router.delete("/users/:id", authenticateUser, async (req, res) => {
  try {
    const userId = req.params.id;
    const requesterId = req.user?.id;
    const requesterRole = req.user?.role;

    // Admin can delete anyone; users can only delete themselves
    if (requesterRole !== "admin" && requesterId !== userId) {
      return res.status(403).json({ error: "Unauthorized action." });
    }

    const [result] = await db.execute("DELETE FROM users WHERE id = ?", [
      userId,
    ]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "User not found." });
    }

    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ error: "Server error during deletion." });
  }
});

// GET user by ID
router.get("/users/:id", authenticateUser, async (req, res) => {
  try {
    const userId = req.params.id;

    // Fetch user from database
    const [users] = await db.execute(
      "SELECT id, username, email, phone, role FROM users WHERE id = ?",
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    // Return user data (excluding sensitive fields like password)
    res.status(200).json({ user: users[0] });
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Route to handle order actions (accepted or rejected)
router.post("/orders/action", async (req, res) => {
  const { orderId, action } = req.body;

  // Validate the action
  if (!["confirmed", "rejected"].includes(action)) {
    return res.status(400).json({ success: false, message: "Invalid action" });
  }
  let connection;
  try {
    // Get a connection from the pool
    connection = await db.getConnection();
    await connection.beginTransaction();

    // Update the order status in the database
    await connection.execute("UPDATE orders SET status = ? WHERE id = ?", [
      action,
      orderId,
    ]);

    // Update the related transaction status
    await connection.execute(
      "UPDATE transactions SET status = ? WHERE order_id = ?",
      [action, orderId]
    );

    // Commit the transaction
    await connection.commit();

    // Send success response
    res
      .status(200)
      .json({ success: true, message: `Order ${orderId} has been ${action}.` });
  } catch (error) {
    if (connection) await connection.rollback(); // Rollback transaction on error
    console.error("Error updating order status:", error);
    res
      .status(500)
      .json({ success: false, message: "Failed to update order status." });
  } finally {
    // Release the connection
    if (connection) connection.release();
  }
});

// Fetch orders for a specific user
router.post("/orders/myorders", async (req, res) => {
  const { userId } = req.body; // User ID from the token

  if (!userId) {
    return res.status(400).json({ message: "User ID is required" });
  }

  try {
    // Fetch orders for the logged-in user
    const [orders] = await db.execute(
      "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC",
      [userId]
    );

    // Send the orders as a response
    res.status(200).json(orders);
  } catch (error) {
    console.error("Error fetching user orders:", error);
    res.status(500).json({ message: "Failed to fetch user orders" });
  }
});

//route to place a payment

// Configure multer to use Cloudinary
/*const paymentStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "payments", // This will create a folder in your Cloudinary account
    allowed_formats: ["jpg", "jpeg", "png"],
  },
});
const uploadPayment = multer({ storage: paymentStorage });*/

// place the payment
router.post("/payments", upload.single("image"), async (req, res) => {
  const { product_name, amount, type, user_id, username, status } = req.body;

  // Validate required fields
  if (!amount) {
    // || image
    return res.status(400).json({
      paymentStatus: false,
      error: "Amount is required.",
    });
  }

  let connection;
  try {
    let imageUrl = null;
    if (req.file) {
      const result = await uploadToCloudinary(
        req.file.buffer,
        req.file.mimetype,
        {
          folder: "payments", // Custom folder
          allowedFormats: ["jpg", "jpeg", "png"], // Custom allowed formats
        }
      );
      imageUrl = result.secure_url;
    }
    // Get a connection from the pool
    connection = await db.getConnection();
    await connection.beginTransaction();

    // Insert the payment into the payments table
    const [paymentResult] = await connection.execute(
      "INSERT INTO payments (product_name, amount, image_path, type, user_id, username, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [product_name, amount, imageUrl, type, user_id, username, status] // Default status
    );

    // Get the inserted payment ID
    const payment_id = paymentResult.insertId;

    // Insert the transaction into the transactions table
    await connection.execute(
      "INSERT INTO transactions (amount, product_name, type, user_id, status, payment_id) VALUES (?, ?, ?, ?, ?, ?)",
      [amount, product_name, type, user_id, status, payment_id]
    );

    // Commit the transaction
    await connection.commit();

    res.status(201).json({
      paymentStatus: true,
      message: "Payment placed successfully!",
    });
  } catch (error) {
    if (connection) await connection.rollback(); // Rollback transaction on error
    console.error("Error placing payment:", error);
    res.status(500).json({
      paymentStatus: false,
      error: "Failed to place the payment. Please try again later.",
    });
  } finally {
    if (connection) connection.release(); // Release the connection
  }
});

// Fetch payments for the authenticated user
router.post("/payments/mypayments", async (req, res) => {
  const { userId } = req.body; // Get userId from request body

  // Validate userId
  if (!userId) {
    return res.status(400).json({
      success: false,
      error: "User ID is required.",
    });
  }

  try {
    const [payments] = await db.execute(
      "SELECT * FROM payments WHERE user_id = ? ORDER BY created_at DESC",
      [userId]
    );

    return res.status(200).json({
      success: true,
      payments: payments, // This will be an empty array if no payments
    });
  } catch (error) {
    console.error("Error fetching payments:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch payments. Please try again later.",
    });
  }
});

// Fetch all  payments
router.get("/waiting-payments", async (req, res) => {
  try {
    const [payments] = await db.execute(
      `SELECT * FROM payments
      ORDER BY created_at DESC`
    );

    if (payments.length === 0) {
      return res.status(404).json({
        success: false,
        message: "No payments found.",
      });
    }

    res.status(200).json({
      success: true,
      payments,
    });
  } catch (error) {
    console.error("Error fetching payments:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch payments. Please try again later.",
    });
  }
});

// Update payment and transaction status (confirm or reject)
router.put("/payments/:paymentId/update-status", async (req, res) => {
  const { paymentId } = req.params;
  const { action } = req.body; // 'confirm' or 'reject'

  if (!action || !["confirmed", "rejected"].includes(action)) {
    return res.status(400).json({
      success: false,
      error: "Invalid action. Use 'confirmed' or 'rejected'.",
    });
  }

  let connection;
  try {
    connection = await db.getConnection();
    await connection.beginTransaction();

    // Determine the new status based on the action
    const newStatus = action === "confirmed" ? "confirmed" : "rejected";

    // Update payment status
    await connection.execute("UPDATE payments SET status = ? WHERE id = ?", [
      newStatus,
      paymentId,
    ]);

    // Update related transaction status
    await connection.execute(
      "UPDATE transactions SET status = ? WHERE payment_id = ?",
      [newStatus, paymentId]
    );

    await connection.commit();

    res.status(200).json({
      success: true,
      message: `Payment ${newStatus} successfully.`,
      color: newStatus === "confirmed" ? "success" : "warning",
    });
  } catch (error) {
    if (connection) await connection.rollback();
    console.error("Error updating payment and transaction status:", error);
    res.status(500).json({
      success: false,
      error:
        "Failed to update payment and transaction status. Please try again later.",
    });
  } finally {
    if (connection) connection.release();
  }
});

// Fetch user transactions
router.get("/profile/:id", authenticateUser, async (req, res) => {
  try {
    const targetUserId = req.params.id.toString();
    const requesterId = req.user.id;
    const requesterRole = req.user.role;
    if (!targetUserId) {
      return res.status(400).json({
        success: false,
        error: "User ID is required.",
      });
    }
    // Authorization check
    if (requesterId !== targetUserId && requesterRole !== "admin") {
      return res.status(403).json({ error: "Access denied" });
    }
    const [transactions] = await db.execute(
      "SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC",
      [targetUserId]
    );
    res.status(200).json({
      success: true,
      transactions, // This will be empty array if no transactions
      message:
        transactions.length > 0
          ? "Transactions retrieved successfully."
          : "No transactions found.",
    });
  } catch (error) {
    console.error("Error fetching transactions:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch transactions. Please try again later.",
    });
  }
});

// create new category
// Multer configuration for categories
/*const categoryStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "categories",
    allowed_formats: ["jpg", "jpeg", "png"],
  },
});

const uploadCategory = multer({ storage: categoryStorage });*/
router.post("/create/category", upload.single("image"), async (req, res) => {
  const { categoryName, section } = req.body;

  // Validate inputs
  if (!categoryName || !section || !req.file) {
    return res.status(400).json({
      categoryStatus: false,
      message: "All fields are required.",
    });
  }

  try {
    // Upload with category-specific settings
    const result = await uploadToCloudinary(
      req.file.buffer,
      req.file.mimetype,
      {
        folder: "categories", // Custom folder
        allowedFormats: ["jpg", "jpeg", "png"], // Custom allowed formats
      }
    );
    // Insert category into the database
    const query = `
      INSERT INTO categories (category_name, section, image)
      VALUES (?, ?, ?)
    `;
    const values = [categoryName, section, result.secure_url];

    const [results] = await db.execute(query, values);

    // Success response
    res.status(201).json({
      categoryStatus: true,
      message: "Category created successfully!",
      categoryId: results.insertId,
    });
  } catch (error) {
    console.error("Error creating category:", error);
    res.status(500).json({
      categoryStatus: false,
      message: "An error occurred. Please try again.",
    });
  }
});

//Fetch created categories
router.get("/categories", async (req, res) => {
  try {
    const query = `
      SELECT *
      FROM categories
    `;

    const [categories] = await db.execute(query);

    // Success response
    res.status(200).json({
      success: true,
      categories,
    });
  } catch (error) {
    console.error("Error fetching categories:", error);
    res.status(500).json({
      success: false,
      message: "An error occurred while fetching categories.",
    });
  }
});

// Configure multer for product file uploads
/*const productStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "products",
    allowed_formats: ["jpg", "jpeg", "png"],
  },
});

const uploadProduct = multer({ storage: productStorage });*/

// Function to sanitize field names
const sanitizeFieldName = (fieldName) => {
  // Replace spaces and special characters with underscores
  return fieldName.replace(/[^a-zA-Z0-9_]/g, "_");
};

// Create new product
router.post("/create/product", upload.single("image"), async (req, res) => {
  const { productName, price, params, category_name, parent_id } = req.body;
  const fields = req.body.fields || [];
  const processedParams = params === "" ? null : params;

  // Validate inputs
  if (!productName || !price || !req.file) {
    return res.status(400).json({
      productStatus: false,
      message: "Please fill all fields and upload an image.",
    });
  }

  if (!category_name || !parent_id) {
    return res.status(400).json({
      productStatus: false,
      message:
        "Please select a category from the existing categories or create a category first.",
    });
  }

  try {
    const result = await uploadToCloudinary(
      req.file.buffer,
      req.file.mimetype,
      {
        folder: "products", // Custom folder
        allowedFormats: ["jpg", "jpeg", "png"], // Custom allowed formats
      }
    );
    // Insert product into the database
    const query = `
      INSERT INTO products (product_name, price, params, category_name, parent_id, image, available)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `;
    const values = [
      productName,
      price,
      processedParams,
      category_name,
      parent_id,
      result.secure_url,
      true,
    ];

    const [results] = await db.execute(query, values);

    // Handle dynamic fields (if any)
    if (fields.length > 0) {
      for (const field of fields) {
        const { fieldName, fieldType, fieldValue } = field;

        // Sanitize the field name
        const sanitizedFieldName = sanitizeFieldName(fieldName);

        // Add column to the products table if it doesn't exist
        const alterQuery = `
          ALTER TABLE products
          ADD COLUMN \`${sanitizedFieldName}\` ${
          fieldType === "NUMBER" ? "INT" : "VARCHAR(255)"
        }
        `;
        await db.execute(alterQuery);

        // Update the newly added column with the field value
        const updateQuery = `
          UPDATE products
          SET \`${sanitizedFieldName}\` = ?
          WHERE id = ?
        `;
        await db.execute(updateQuery, [fieldValue, results.insertId]);
      }
    }

    // Success response
    res.status(201).json({
      productStatus: true,
      message: "Product created successfully!",
      productId: results.insertId,
    });
  } catch (error) {
    console.error("Error creating product:", error);
    res.status(500).json({
      productStatus: false,
      message: "An error occurred. Please try again.",
    });
  }
});

// Delete a product
router.delete("/delete/product/:id", async (req, res) => {
  const productId = req.params.id;

  // Validate ID format first to prevent unnecessary DB calls
  if (!productId || isNaN(productId)) {
    return res.status(400).json({
      deleteStatus: false,
      message: "Valid numeric product ID is required",
    });
  }

  try {
    // Single atomic operation combining existence check and deletion
    const [result] = await db.execute(
      "DELETE FROM products WHERE id = ? LIMIT 1",
      [productId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        deleteStatus: false,
        message: "Product not found",
      });
    }

    // Successful deletion
    return res.status(200).json({
      deleteStatus: true,
      message: "Product deleted successfully",
    });
  } catch (error) {
    console.error("Database error:", error);
    return res.status(500).json({
      deleteStatus: false,
      message: "Database operation failed",
    });
  }
});

// Fetch products from the database
router.get("/products", async (req, res) => {
  try {
    // Query to fetch products
    const query = `
      SELECT *
      FROM products
    `;

    // Execute the query
    const [products] = await db.execute(query);

    // Send the products as a response
    res.status(200).json(products);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ error: "Failed to fetch products" });
  }
});

//make a category available or unavailable
router.put("/categories/:id/availability", async (req, res) => {
  const { id } = req.params;
  const { available } = req.body;

  try {
    // Update the availability in the database
    const query = `
      UPDATE categories
      SET available = ?
      WHERE id = ?
    `;
    await db.execute(query, [available ? 1 : 0, id]);

    // Send a success response
    res.status(200).json({ success: true });
  } catch (error) {
    console.error("Error updating the category:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to update the category" });
  }
});

//make a product available or unavailable
router.put("/products/:id/availability", async (req, res) => {
  const { id } = req.params;
  const { available } = req.body;

  try {
    // Update the availability in the database
    const query = `
      UPDATE products
      SET available = ?
      WHERE id = ?
    `;
    await db.execute(query, [available ? 1 : 0, id]);

    // Send a success response
    res.status(200).json({ success: true });
  } catch (error) {
    console.error("Error updating the product:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to update the product" });
  }
});

// user balance
router.get("/balance", async (req, res) => {
  const { user_id } = req.query;

  if (!user_id) {
    return res.status(400).json({ error: "User ID is required." });
  }

  try {
    const [result] = await db.query(
      `SELECT 
         SUM(CASE 
               WHEN type = 'IN' THEN amount 
               WHEN type = 'OUT' THEN -amount 
               ELSE 0 
             END) AS balance
       FROM transactions
        WHERE user_id = ? AND status IN ('confirmed', 'waiting')`,
      [user_id]
    );

    const balance = result[0].balance || 0; // Default to 0 if no transactions exist
    res.status(200).json({ balance });
  } catch (err) {
    console.error("Error fetching balance:", err);
    res.status(500).json({ error: "Failed to fetch balance." });
  }
});

export default router;
