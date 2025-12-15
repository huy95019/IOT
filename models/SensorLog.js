import mongoose from "mongoose";

const sensorLogSchema = new mongoose.Schema({
  type: String,      // soil | temp | humid
  value: Number,
  time: { type: Date, default: Date.now }
});

export default mongoose.model("SensorLog", sensorLogSchema);
