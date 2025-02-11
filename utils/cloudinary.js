// utils/cloudinary.js
import { v2 as cloudinary } from "cloudinary";

export const uploadToCloudinary = async (
  fileBuffer,
  mimetype,
  options = {}
) => {
  try {
    const dataUri = `data:${mimetype};base64,${fileBuffer.toString("base64")}`;
    const result = await cloudinary.uploader.upload(dataUri, {
      folder: options.folder || "default", // Default folder if none specified
      allowed_formats: options.allowedFormats || ["jpg", "jpeg", "png"],
      ...options, // Spread any additional Cloudinary options
    });
    return result;
  } catch (error) {
    throw new Error(`Cloudinary upload failed: ${error.message}`);
  }
};
