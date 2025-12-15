import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String, // đã hash
  role: { type: String, default: "user" }
});

export default mongoose.model("User", userSchema);
