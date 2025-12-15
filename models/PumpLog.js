import mongoose from "mongoose";

const pumpLogSchema = new mongoose.Schema({
  state: String,
  speed: Number,
  mode: String,
  time: { type: Date, default: Date.now }
});

export default mongoose.model("PumpLog", pumpLogSchema);
