// server.js
import mqtt from "mqtt";
import admin from "firebase-admin";
import fs from "fs";
import mongoose from "mongoose";
import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";

import User from "./models/User.js";
import SensorLog from "./models/SensorLog.js";

import dotenv from 'dotenv';
dotenv.config();

/* ===================== CONFIG ===================== */
const JWT_SECRET = "SECRET_BTL_IOT";

/* ===================== EXPRESS ===================== */
const app = express();
app.use(cors());
app.use(express.json());

/* ===================== MONGODB ===================== */
mongoose.connect("mongodb+srv://huy95019_db_user:<db_password>@cluster0.nghmqyv.mongodb.net/?appName=Cluster0", {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("✔ MongoDB connected"));

/* ===================== FIREBASE ===================== */
const serviceAccount = JSON.parse(
  process.env.FIREBASE_SERVICE_ACCOUNT
);


admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL:
    "https://httc-696a3-default-rtdb.asia-southeast1.firebasedatabase.app"
});
const db = admin.database();

/* ===================== MQTT ===================== */
const mqttUrl =
  "mqtts://e68c201b89484d92ac83e57b5ac0d2be.s1.eu.hivemq.cloud:8883";

const mqttClient = mqtt.connect(mqttUrl, {
  username: "HuyNong",
  password: "Quanghuy2004",
  reconnectPeriod: 2000,
  rejectUnauthorized: false
});

mqttClient.on("connect", () => {
  console.log("✔ MQTT connected");
  mqttClient.subscribe("iot/plant/#");
});

mqttClient.on("message", async (topic, payload) => {
  const p = payload.toString();
  console.log("MQTT:", topic, p);

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
});

/* ===================== AUTH API ===================== */

// Register (chạy 1 lần)
app.post("/api/register", async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 10);
  const user = await User.create({
    username: req.body.username,
    password: hash
  });
  res.json(user);
});

// Login
app.post("/api/login", async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  if (!user) return res.status(401).json({ msg: "User not found" });

  const ok = await bcrypt.compare(req.body.password, user.password);
  if (!ok) return res.status(401).json({ msg: "Wrong password" });

  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1d" });
  res.json({ token });
});

/* ===================== COMMAND API ===================== */
function auth(req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1];
    jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.sendStatus(401);
  }
}

app.post("/api/pump", auth, (req, res) => {
  db.ref("commands/pump_set").set(req.body.state);
  res.json({ ok: true });
});

/* ===================== START SERVER ===================== */
app.listen(3000, () => {
  console.log("✔ Server running http://localhost:3000");
});
