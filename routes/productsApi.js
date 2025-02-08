import express from "express";
import axios from "axios";

const router = express.Router();

const API_BASE_URL = "https://api.flashvision.co/client/api";
const API_TOKEN = process.env.API_TOKEN;
// Fetch categories
router.get("/categories", async (req, res) => {
  try {
    const { data } = await axios.get(`${API_BASE_URL}/categories`, {
      headers: { "api-token": API_TOKEN },
    });
    res.json(data);
  } catch (error) {
    console.error("Error fetching categories:", error.message);
    res.status(500).json({ error: "Failed to fetch categories" });
  }
});

// Fetch products
router.get("/products", async (req, res) => {
  try {
    const { data } = await axios.get(`${API_BASE_URL}/products`, {
      headers: { "api-token": API_TOKEN },
    });
    res.json(data);
  } catch (error) {
    console.error("Error fetching products:", error.message);
    res.status(500).json({ error: "Failed to fetch products" });
  }
});

export default router;
