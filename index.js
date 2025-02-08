import express from "express";
import cors from "cors";
import { fileURLToPath } from "url";
import cookieParser from "cookie-parser";
import routes from "./routes/routes.js"; // Import routes
import externalRoutes from "./routes/productsApi.js"; // External API routes
import "dotenv/config";
import path from "path";
const app = express();
// || 5000 for local
const PORT = process.env.PORT || 8080;

// Define __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// Middlewares
// Enable CORS
console.log("CORS origin:", process.env.CLIENT_URL);
app.use(
  cors({
    origin: process.env.CLIENT_URL, // Your frontend URL
    credentials: true, // Allow sending cookies
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
  })
);

// Add OPTIONS handler here
app.options("*", (req, res) => {
  res.header("Access-Control-Allow-Origin", process.env.CLIENT_URL);
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, Cookie"
  );
  res.sendStatus(204);
});

app.use(express.json()); // Parse incoming JSON bodies
app.use(express.urlencoded({ extended: true })); // For URL-encoded data
app.use(cookieParser()); // To parse cookies
app.use("/uploads", express.static("uploads"));
// Internal routes (e.g., sign-in, sign-up)
app.use("/api", routes); // Prefix the routes with /api

// External API routes (e.g., products, categories)
app.use("/external", externalRoutes);

// In production, serve static files from React build
if (process.env.NODE_ENV === "production") {
  app.use(express.static(path.join(__dirname, "../bermuda-web/dist")));
  app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "../bermuda-web/dist/index.html"));
  });
}
// Start the server
app.listen(PORT, () => {
  console.log(`Server running in ${process.env.NODE_ENV} on port ${PORT}`);
});
