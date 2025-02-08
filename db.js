import "dotenv/config";
import mysql from "mysql2/promise";
// Create MySQL connection
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
  // Additional recommended configurations
  connectTimeout: 10000, // 10 seconds
});

// Handle pool errors
pool.on("error", (err) => {
  console.error("Unexpected error on idle client", {
    error: err.message,
    code: err.code,
    timestamp: new Date().toISOString(),
  });
  process.exit(-1);
});

(async () => {
  try {
    const connection = await pool.getConnection();
    console.log("MySQL connected");
    connection.release(); // Release the connection back to the pool
  } catch (error) {
    console.error("MySQL connection error:", {
      message: error.message,
      code: error.code,
      timestamp: new Date().toISOString(),
    });

    // Exit if we can't establish initial connection
    process.exit(-1);
  }
})();

export default pool;
