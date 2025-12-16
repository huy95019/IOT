import mqtt from "mqtt";
import admin from "firebase-admin";
import mongoose from "mongoose";
import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";

// Giả định các models này có trường 'email'
import User from "./models/User.js";
import SensorLog from "./models/SensorLog.js";

dotenv.config();

/* ===================== CONFIG ===================== */
const JWT_SECRET = process.env.JWT_SECRET || "SECRET_BTL_IOT";

/* ===================== EXPRESS ===================== */
const app = express();
app.use(cors());
app.use(express.json());

// 👉 SERVE FRONTEND
app.use(express.static("public"));

// 👉 TRANG CHỦ → LOGIN
app.get("/", (_req, res) => {
  // Đảm bảo bạn có file public/login.html
  res.sendFile(path.resolve("public/login.html"));
});

/* ===================== MONGODB ===================== */
if (!process.env.MONGO_URI) {
  console.error("❌ Missing MONGO_URI");
  process.exit(1);
}

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✔ MongoDB connected"))
  .catch(err => {
    console.error("❌ MongoDB error:", err.message);
    process.exit(1);
  });

/* ===================== FIREBASE ===================== */
if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
  console.error("❌ Missing FIREBASE_SERVICE_ACCOUNT");
  process.exit(1);
}

let serviceAccount;
try {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} catch (err) {
  console.error("❌ FIREBASE_SERVICE_ACCOUNT invalid JSON");
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL:
    "https://httc-696a3-default-rtdb.asia-southeast1.firebasedatabase.app"
});

const db = admin.database();
console.log("✔ Firebase initialized");

/* ===================== MQTT ===================== */
const mqttClient = mqtt.connect(
  "mqtts://e68c201b89484d92ac83e57b5ac0d2be.s1.eu.hivemq.cloud:8883",
  {
    username: process.env.MQTT_USER || "HuyNong",
    password: process.env.MQTT_PASS || "Quanghuy2004",
    reconnectPeriod: 2000,
    rejectUnauthorized: false
  }
);

mqttClient.on("connect", () => {
  console.log("✔ MQTT connected");
  mqttClient.subscribe("iot/plant/#");
});

mqttClient.on("message", async (topic, payload) => {
  const p = payload.toString();
  console.log("MQTT:", topic, p);

  try {
    if (topic === "iot/plant/soil") {
      db.ref("sensor/soil").set({ value: Number(p), time: Date.now() });
      await SensorLog.create({ type: "soil", value: Number(p) });
    }

    if (topic === "iot/plant/temp") {
      db.ref("sensor/temp").set({ value: Number(p), time: Date.now() });
      await SensorLog.create({ type: "temp", value: Number(p) });
    }

    if (topic === "iot/plant/humid") {
      db.ref("sensor/humi").set({ value: Number(p), time: Date.now() });
      await SensorLog.create({ type: "humid", value: Number(p) });
    }

    if (topic === "iot/plant/pump/state") {
      db.ref("pump/state").set(p);
    }

    if (topic === "iot/plant/pump/speed/state") {
      db.ref("pump/speed").set(Number(p));
    }
  } catch (err) {
    console.error("❌ MQTT handler error:", err.message);
  }
});

/* ===================== AUTH API ===================== */

// REGISTER (SỬA ĐỔI: Sử dụng email thay vì username)
app.post("/api/register", async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 10);
  const user = await User.create({
    // Đã sửa: Lấy email từ body
    email: req.body.email, 
    password: hash
  });
  res.json(user);
});

// LOGIN (SỬA ĐỔI: Sử dụng email thay vì username)
app.post("/api/login", async (req, res) => {
  // Lấy email và password từ body của yêu cầu POST
  const { email, password } = req.body; 

  // Tìm kiếm người dùng bằng email
  const user = await User.findOne({ email });
  
  // Nếu không tìm thấy người dùng
  if (!user) {
    return res.status(401).json({ msg: "Email hoặc Mật khẩu không đúng." });
  }

  // So sánh mật khẩu đã nhập với mật khẩu đã mã hóa trong database
  const ok = await bcrypt.compare(password, user.password);
  
  // Nếu mật khẩu không khớp
  if (!ok) {
    return res.status(401).json({ msg: "Email hoặc Mật khẩu không đúng." });
  }

  // Tạo và trả về JWT token
  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1d" });
  res.json({ token });
});

/* ===================== AUTH MIDDLEWARE ===================== */
function auth(req, res, next) {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.sendStatus(401);
  }
}

/* ===================== COMMAND API ===================== */
app.post("/api/pump", auth, (req, res) => {
  db.ref("commands/pump_set").set(req.body.state);
  res.json({ ok: true });
});

/* ===================== START SERVER ===================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✔ Server running on port ${PORT}`);
});