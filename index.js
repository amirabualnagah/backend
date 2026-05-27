require("dotenv").config()

const express = require("express")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcryptjs")
const axios = require("axios")
const cors = require("cors")
const fs = require("fs")
const mysql = require("mysql2/promise")
const passport = require("passport")
const session = require("express-session")
const { Strategy: GoogleStrategy } = require("passport-google-oauth20")
const { RouterOSAPI } = require("node-routeros")

const app = express()

app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:5173",
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}))
app.use(express.json())
app.use(session({
  secret: process.env.JWT_SECRET || "wifi_secret_key",
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 5 * 60 * 1000 },
}))
app.use(passport.initialize())
app.use(passport.session())

/* ================================================================
   Constants
================================================================ */

const PORT = process.env.PORT || 5000
const JWT_SECRET = process.env.JWT_SECRET || "wifi_secret_key"
const PAYMOB_API_KEY = process.env.PAYMOB_API_KEY
const PAYMOB_INTEGRATION_ID = Number(process.env.PAYMOB_INTEGRATION_ID)
const PAYMOB_IFRAME_ID = process.env.PAYMOB_IFRAME_ID
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173"

/* ================================================================
   MySQL — App Database
================================================================ */

const db = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "wifi_system",
  waitForConnections: true,
  connectionLimit: 10,
})

/* ================================================================
   RADIUS Manager
================================================================ */

let radiusPool = null

function getRadiusConfig() {
  try { return JSON.parse(fs.readFileSync("./radius-config.json", "utf8")) }
  catch { return null }
}

function buildRadiusPool(cfg) {
  if (radiusPool) radiusPool.end().catch(() => { })
  radiusPool = mysql.createPool({
    host: cfg.host,
    port: Number(cfg.port) || 3306,
    user: cfg.username,
    password: cfg.password,
    database: cfg.database || "radius",
    waitForConnections: true,
    connectionLimit: 5,
    connectTimeout: 6000,
  })
  return radiusPool
}

const savedRadiusCfg = getRadiusConfig()
if (savedRadiusCfg) buildRadiusPool(savedRadiusCfg)

async function radiusQuery(sql, params = []) {
  if (!radiusPool) throw new Error("RADIUS غير مضبوط")
  const [rows] = await radiusPool.query(sql, params)
  return rows
}

/* ================================================================
   System Toggles
================================================================ */

function getSystemToggles() {
  try {
    const t = JSON.parse(fs.readFileSync("./system-toggles.json", "utf8"))
    // payments_enabled مستقل عن حالة الميكروتك/RADIUS
    if (t.payments_enabled === undefined) t.payments_enabled = true
    return t
  } catch {
    return { mode: null, mikrotik: true, radius: true, payments_enabled: true }
  }
}

function saveSystemToggles(t) {
  fs.writeFileSync("./system-toggles.json", JSON.stringify(t, null, 2))
}

/* ================================================================
   DB Init
================================================================ */

async function initDB() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        username   VARCHAR(150) UNIQUE NOT NULL,
        password   TEXT,
        name       VARCHAR(100),
        role       VARCHAR(10)  DEFAULT 'user',
        google_id  VARCHAR(100) UNIQUE DEFAULT NULL,
        email      VARCHAR(150) DEFAULT NULL,
        avatar     VARCHAR(255) DEFAULT NULL,
        created_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
      )`)

    // Safe migrations — ignored if column already exists
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id VARCHAR(100) UNIQUE DEFAULT NULL`).catch(() => { })
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email      VARCHAR(150) DEFAULT NULL`).catch(() => { })
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar     VARCHAR(255) DEFAULT NULL`).catch(() => { })

    await db.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id               INT AUTO_INCREMENT PRIMARY KEY,
        user_id          INT          NOT NULL,
        username         VARCHAR(50),
        user_name        VARCHAR(100),
        plan_id          VARCHAR(20),
        plan_name        VARCHAR(50),
        amount           INT,
        status           VARCHAR(20)  DEFAULT 'pending',
        voucher_user     VARCHAR(50),
        voucher_pass     VARCHAR(50),
        voucher_days     INT,
        voucher_download VARCHAR(20),
        voucher_upload   VARCHAR(20),
        provider         VARCHAR(20)  DEFAULT 'mikrotik',
        created_at       TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
      )`)

    await db.query(`
      CREATE TABLE IF NOT EXISTS plans (
        id       VARCHAR(20) PRIMARY KEY,
        name     VARCHAR(50)  NOT NULL,
        price    INT          NOT NULL,
        days     INT          DEFAULT 30,
        download VARCHAR(20)  DEFAULT '10M',
        upload   VARCHAR(20)  DEFAULT '5M',
        popular  TINYINT      DEFAULT 0
      )`)

    await db.query(`
      INSERT IGNORE INTO plans (id, name, price, days, download, upload, popular) VALUES
        ('basic',    '10GB', 50,  30, '10M', '5M',  0),
        ('standard', '25GB', 100, 30, '25M', '10M', 1),
        ('premium',  '50GB', 180, 30, '50M', '20M', 0)`)

    const [admins] = await db.query("SELECT id FROM users WHERE username = 'admin'")
    if (admins.length === 0) {
      const hashed = await bcrypt.hash("admin123", 10)
      await db.query(
        "INSERT INTO users (username, password, name, role) VALUES (?, ?, ?, ?)",
        ["admin", hashed, "Admin", "admin"])
    }

    console.log("✅ Database initialized")
  } catch (err) {
    console.error("❌ DB init error:", err.message)
  }
}

initDB()

/* ================================================================
   Google OAuth
================================================================ */

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || "http://localhost:5000/auth/google/callback",
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const googleId = profile.id
    const email = profile.emails?.[0]?.value || ""
    const name = profile.displayName || ""
    const avatar = profile.photos?.[0]?.value || ""

    const [existing] = await db.query("SELECT * FROM users WHERE google_id = ?", [googleId])
    if (existing.length > 0) return done(null, existing[0])

    if (email) {
      const [byEmail] = await db.query("SELECT * FROM users WHERE username = ?", [email])
      if (byEmail.length > 0) {
        await db.query(
          "UPDATE users SET google_id = ?, avatar = ? WHERE id = ?",
          [googleId, avatar, byEmail[0].id])
        return done(null, byEmail[0])
      }
    }

    const username = email || `google_${googleId}`
    const [result] = await db.query(
      "INSERT INTO users (username, password, name, role, google_id, email, avatar) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [username, "", name, "user", googleId, email, avatar])
    const [newUser] = await db.query("SELECT * FROM users WHERE id = ?", [result.insertId])
    return done(null, newUser[0])
  } catch (err) {
    return done(err, null)
  }
}))

passport.serializeUser((user, done) => done(null, user.id))
passport.deserializeUser(async (id, done) => {
  try {
    const [rows] = await db.query("SELECT * FROM users WHERE id = ?", [id])
    done(null, rows[0] || null)
  } catch (err) {
    done(err, null)
  }
})

/* ================================================================
   Mikrotik
================================================================ */

let mikrotikConfig = (() => {
  try {
    const json = JSON.parse(fs.readFileSync("./mikrotik-config.json", "utf8"))
    if (json.host) return json
  } catch { }
  if (process.env.MIKROTIK_HOST) {
    return {
      host: process.env.MIKROTIK_HOST,
      port: process.env.MIKROTIK_PORT || 8728,
      username: process.env.MIKROTIK_USER,
      password: process.env.MIKROTIK_PASS,
    }
  }
  return { host: "", port: 8728, username: "", password: "" }
})()

async function getMikrotikConnection() {
  const conn = new RouterOSAPI({
    host: mikrotikConfig.host,
    user: mikrotikConfig.username,
    password: mikrotikConfig.password,
    port: Number(mikrotikConfig.port) || 8728,
    timeout: 5,
  })
  await conn.connect()
  return conn
}

/* ================================================================
   Voucher Generator
================================================================ */

function generateVoucher(orderId, plan) {
  return {
    username: `${orderId}${Date.now().toString().slice(-6)}`,
    password: Math.floor(10000000 + Math.random() * 90000000).toString(),
    planName: plan.name || "",
    days: plan.days || 30,
    download: plan.download || "10M",
    upload: plan.upload || "5M",
  }
}

/* ================================================================
   Utility Functions
================================================================ */

function formatDuration(seconds) {
  if (!seconds) return "0s"
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = seconds % 60
  if (h > 0) return `${h}h ${m}m`
  if (m > 0) return `${m}m ${s}s`
  return `${s}s`
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 B"
  const units = ["B", "KB", "MB", "GB", "TB"]
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`
}

/* ================================================================
   Middleware
================================================================ */

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1]
  if (!token) return res.status(401).json({ error: "No token" })
  try {
    req.user = jwt.verify(token, JWT_SECRET)
    next()
  } catch {
    res.status(401).json({ error: "Invalid token" })
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin")
    return res.status(403).json({ error: "Admin only" })
  next()
}

/* ================================================================
   Server Readiness Check
================================================================ */

async function checkServerReady() {
  const toggles = getSystemToggles()
  if (!toggles.mode) return false

  let mkOnline = false
  let radOnline = false

  if ((toggles.mode === "mikrotik" || toggles.mode === "both") && toggles.mikrotik && mikrotikConfig.host) {
    try {
      const conn = await getMikrotikConnection()
      conn.close()
      mkOnline = true
    } catch { }
  }

  if ((toggles.mode === "radius" || toggles.mode === "both") && toggles.radius && radiusPool) {
    try {
      await radiusQuery("SELECT 1")
      radOnline = true
    } catch { }
  }

  if (toggles.mode === "mikrotik") return mkOnline
  if (toggles.mode === "radius") return radOnline
  if (toggles.mode === "both") return mkOnline && radOnline
  return false
}

/* ================================================================
   Auto Server Health Check
   - بيفحص الميكروتك/RADIUS كل 30 ثانية
   - لو السرفر وقع: يوقف الشحن تلقائياً (auto_paused = true)
   - لو السرفر رجع: يشغّل الشحن تلقائياً
   - الفصل اليدوي من الأدمن (manual_pause) مستقل ومش بيتأثر
================================================================ */

let _healthChecking = false

async function runHealthCheck() {
  if (_healthChecking) return
  _healthChecking = true
  try {
    const toggles = getSystemToggles()

    // لو مفيش mode متضبط — مش هيفحص
    if (!toggles.mode) { _healthChecking = false; return }

    let serverOnline = false

    if ((toggles.mode === "mikrotik" || toggles.mode === "both") && mikrotikConfig.host) {
      try { const c = await getMikrotikConnection(); c.close(); serverOnline = true } catch { }
    } else if (toggles.mode === "radius" && radiusPool) {
      try { await radiusQuery("SELECT 1"); serverOnline = true } catch { }
    } else if (toggles.mode === "both" && radiusPool) {
      try { await radiusQuery("SELECT 1"); serverOnline = true } catch { }
    }

    // لو السرفر وقع: سجّل auto_paused
    if (!serverOnline && !toggles.auto_paused) {
      toggles.auto_paused = true
      saveSystemToggles(toggles)
      console.log("⚠️  Auto-paused payments — server offline")
    }

    // لو السرفر رجع وكان auto_paused: شغّل الشحن تاني
    if (serverOnline && toggles.auto_paused) {
      toggles.auto_paused = false
      saveSystemToggles(toggles)
      console.log("✅  Auto-resumed payments — server back online")
    }
  } finally {
    _healthChecking = false
  }
}

// فحص كل 30 ثانية
runHealthCheck()
setInterval(runHealthCheck, 30_000)

/* ================================================================
   RADIUS Helper Functions
================================================================ */

async function addRadiusUser(username, password, plan = {}) {
  const days = plan.days || 30
  const download = plan.download || "10M"
  const upload = plan.upload || "5M"
  const expiry = new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10)

  await radiusQuery(
    `INSERT INTO radcheck (username, attribute, op, value)
     VALUES (?, 'Cleartext-Password', ':=', ?)
     ON DUPLICATE KEY UPDATE value = VALUES(value)`,
    [username, password])

  await radiusQuery(
    `INSERT INTO radreply (username, attribute, op, value)
     VALUES (?, 'Mikrotik-Rate-Limit', '=', ?)
     ON DUPLICATE KEY UPDATE value = VALUES(value)`,
    [username, `${download}/${upload}`])

  await radiusQuery(`
    INSERT INTO rm_users (
      username, password, downlimit, uplimit, comblimit,
      firstname, lastname, expiration, enableuser, uptimelimit,
      srvid, createdon, acctype, createdby, credits, owner, groupid, lang
    ) VALUES (
      ?, MD5(?), '0', '0', '0', '', '',
      ?, '1', '0', '0', NOW(), '0', 'admin', '0.00', 'admin', '1', 'Arabic-4.1'
    )`,
    [username, password, expiry])

  await radiusQuery(`
    INSERT INTO rm_changesrv (
      username, newsrvid, newsrvname, scheduledate, requestdate, status, requested
    ) VALUES (?, '0', 'Default service', NOW(), NOW(), 1, 'admin')`,
    [username])

  if (plan.name) {
    await radiusQuery(
      `INSERT IGNORE INTO radusergroup (username, groupname, priority) VALUES (?, ?, 1)`,
      [username, plan.name])
  }
}

async function deleteRadiusUser(username) {
  await radiusQuery("DELETE FROM radcheck     WHERE username = ?", [username])
  await radiusQuery("DELETE FROM radreply     WHERE username = ?", [username])
  await radiusQuery("DELETE FROM radusergroup WHERE username = ?", [username])
}

async function getActiveSessions() {
  return radiusQuery(`
    SELECT radacctid, username,
      nasipaddress       AS nas,
      framedipaddress    AS ip,
      callingstationid   AS mac,
      acctsessiontime    AS duration_sec,
      acctinputoctets    AS bytes_up,
      acctoutputoctets   AS bytes_down,
      acctstarttime      AS started_at,
      acctstoptime       AS stopped_at,
      acctterminatecause AS terminate_cause
    FROM radacct
    WHERE acctstoptime IS NULL
    ORDER BY acctstarttime DESC`)
}

async function getUserSessions(username) {
  return radiusQuery(`
    SELECT radacctid,
      nasipaddress       AS nas,
      framedipaddress    AS ip,
      callingstationid   AS mac,
      acctsessiontime    AS duration_sec,
      acctinputoctets    AS bytes_up,
      acctoutputoctets   AS bytes_down,
      acctstarttime      AS started_at,
      acctstoptime       AS stopped_at,
      acctterminatecause AS terminate_cause
    FROM radacct
    WHERE username = ?
    ORDER BY acctstarttime DESC
    LIMIT 50`,
    [username])
}

/* ================================================================
   Order Activation
================================================================ */

async function activateOrder(order) {
  const toggles = getSystemToggles()
  const [plans] = await db.query("SELECT * FROM plans WHERE id = ?", [order.plan_id])
  const plan = plans[0] || {}
  const voucher = generateVoucher(order.id, plan)

  await db.query(
    `UPDATE orders
     SET status=?, voucher_user=?, voucher_pass=?, voucher_days=?, voucher_download=?, voucher_upload=?
     WHERE id=?`,
    ["paid", voucher.username, voucher.password, voucher.days, voucher.download, voucher.upload, order.id])

  if ((toggles.mode === "mikrotik" || toggles.mode === "both") && toggles.mikrotik) {
    try {
      const conn = await getMikrotikConnection()
      await conn.write([
        "/ip/hotspot/user/add",
        `=name=${voucher.username}`,
        `=password=${voucher.password}`,
        `=limit-uptime=${plan.days || 30}d`,
        `=comment=Order #${order.id} - ${order.user_name}`,
      ])
      conn.close()
      console.log(`✅ Mikrotik user added: ${voucher.username}`)
    } catch (err) {
      console.error("⚠️ Mikrotik error:", err.message)
    }
  }

  if ((toggles.mode === "radius" || toggles.mode === "both") && toggles.radius && radiusPool) {
    try {
      await addRadiusUser(voucher.username, voucher.password, plan)
      console.log(`✅ RADIUS user added: ${voucher.username}`)
    } catch (err) {
      console.error("⚠️ RADIUS error:", err.message)
    }
  }

  return voucher
}

/* ================================================================
   Routes — Auth
================================================================ */

app.post("/register", async (req, res) => {
  const { username, password, name } = req.body
  if (!username || !password) return res.status(400).json({ error: "Missing fields" })
  try {
    const [existing] = await db.query("SELECT id FROM users WHERE username = ?", [username])
    if (existing.length > 0) return res.status(400).json({ error: "Username exists" })
    const hashed = await bcrypt.hash(password, 10)
    await db.query(
      "INSERT INTO users (username, password, name, role) VALUES (?, ?, ?, ?)",
      [username, hashed, name || username, "user"])
    res.json({ message: "Registered" })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post("/login", async (req, res) => {
  const { username, password } = req.body
  try {
    const [rows] = await db.query("SELECT * FROM users WHERE username = ?", [username])
    if (rows.length === 0) return res.status(401).json({ error: "Invalid credentials" })
    const user = rows[0]
    if (!user.password)
      return res.status(401).json({ error: "هذا الحساب مسجّل عبر Google — سجّل دخولك بـ Google" })
    if (!await bcrypt.compare(password, user.password))
      return res.status(401).json({ error: "Invalid credentials" })
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, name: user.name },
      JWT_SECRET, { expiresIn: "7d" })
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, name: user.name } })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

/* ================================================================
   Routes — Google OAuth
================================================================ */

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] }))

app.get("/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: `${FRONTEND_URL}/login?error=google_failed`,
    session: true,
  }),
  (req, res) => {
    const user = req.user
    if (!user) return res.redirect(`${FRONTEND_URL}/login?error=google_failed`)
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, name: user.name },
      JWT_SECRET, { expiresIn: "7d" })
    req.logout(() => { })
    res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}&role=${user.role}`)
  })

/* ================================================================
   Routes — Plans
================================================================ */

app.get("/plans", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM plans")
    res.json(rows.map(p => ({
      ...p,
      popular: !!p.popular,
      duration: `${p.days} يوم`,
      speed: `${p.download} تحميل`,
    })))
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

/* ================================================================
   Routes — Server Status (user-facing)
================================================================ */

app.get("/server-status", (req, res) => {
  const toggles = getSystemToggles()
  // متاح لو: مش موقوف يدوياً ومش موقوف تلقائياً
  const manualOff = toggles.payments_enabled === false
  const autoOff   = toggles.auto_paused === true
  res.json({ available: !manualOff && !autoOff, manual_pause: manualOff, auto_pause: autoOff })
})

/* ================================================================
   Routes — My Orders
================================================================ */

app.get("/my-orders", auth, async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC",
      [req.user.id])
    res.json(rows.map(o => ({
      id: o.id,
      planId: o.plan_id,
      planName: o.plan_name,
      amount: o.amount,
      status: o.status,
      createdAt: o.created_at,
      provider: o.provider || "mikrotik",
      voucher: o.status === "paid" ? {
        username: o.voucher_user,
        password: o.voucher_pass,
        days: o.voucher_days,
        download: o.voucher_download,
        upload: o.voucher_upload,
        planName: o.plan_name,
      } : null,
    })))
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

/* ================================================================
   Routes — Checkout
================================================================ */

app.post("/checkout", auth, async (req, res) => {
  const { planId } = req.body

  const toggles = getSystemToggles()
  if (toggles.payments_enabled === false)
    return res.status(503).json({ error: "الشحن متوقف — تواصل مع الدعم" })
  if (toggles.auto_paused)
    return res.status(503).json({ error: "الشحن متوقف مؤقتاً — السرفر أوفلاين" })

  try {
    const [plans] = await db.query("SELECT * FROM plans WHERE id = ?", [planId])
    if (plans.length === 0) return res.status(400).json({ error: "Invalid plan" })

    const plan = plans[0]
    const price = Number(plan.price)

    const [result] = await db.query(
      "INSERT INTO orders (user_id, username, user_name, plan_id, plan_name, amount, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [req.user.id, req.user.username, req.user.name, planId, plan.name, price, "pending"])

    const orderId = result.insertId

    const authRes = await axios.post("https://accept.paymob.com/api/auth/tokens",
      { api_key: PAYMOB_API_KEY })
    const token = authRes.data.token

    const orderRes = await axios.post("https://accept.paymob.com/api/ecommerce/orders", {
      auth_token: token,
      delivery_needed: false,
      amount_cents: price * 100,
      currency: "EGP",
      items: [],
      merchant_order_id: `${orderId}_${Date.now()}`,
    })

    const paymentKey = await axios.post("https://accept.paymob.com/api/acceptance/payment_keys", {
      auth_token: token,
      amount_cents: price * 100,
      expiration: 3600,
      order_id: orderRes.data.id,
      currency: "EGP",
      integration_id: PAYMOB_INTEGRATION_ID,
      billing_data: {
        first_name: req.user.name || "wifi",
        last_name: "user",
        email: "test@test.com",
        phone_number: "01000000000",
        country: "EG",
        city: "Cairo",
        street: "NA",
        building: "NA",
        floor: "NA",
        apartment: "NA",
      },
    })

    res.json({
      iframeUrl: `https://accept.paymob.com/api/acceptance/iframes/${PAYMOB_IFRAME_ID}?payment_token=${paymentKey.data.token}`,
    })
  } catch (err) {
    console.error("❌ Checkout error:", err.response?.data || err.message)
    res.status(500).json({ error: "فشل بدء الدفع" })
  }
})

/* ================================================================
   Routes — Payment Callback (Webhook)
================================================================ */

app.post("/payment-callback", async (req, res) => {
  const data = req.body.obj || req.body
  const { success, merchant_order_id } = data
  try {
    const realOrderId = merchant_order_id.toString().split("_")[0]
    const [rows] = await db.query("SELECT * FROM orders WHERE id = ?", [Number(realOrderId)])
    if (rows.length === 0) return res.json({ status: "notfound" })
    const order = rows[0]
    if (success === true || success === "true") {
      await activateOrder(order)
    } else {
      await db.query("UPDATE orders SET status=? WHERE id=?", ["failed", order.id])
    }
    res.json({ status: "ok" })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

/* ================================================================
   Routes — Success Redirect
================================================================ */

app.get("/success", async (req, res) => {
  const { merchant_order_id, success } = req.query
  if (success !== "true") return res.redirect(`${FRONTEND_URL}/success?error=not_paid`)
  try {
    const realOrderId = merchant_order_id.toString().split("_")[0]
    const [rows] = await db.query("SELECT * FROM orders WHERE id = ?", [Number(realOrderId)])
    if (rows.length === 0) return res.redirect(`${FRONTEND_URL}/success?error=not_found`)
    const order = rows[0]
    if (order.status === "pending") await activateOrder(order)
    const [updated] = await db.query("SELECT * FROM orders WHERE id = ?", [order.id])
    const o = updated[0]
    if (o.status === "paid")
      return res.redirect(`${FRONTEND_URL}/success?user=${o.voucher_user}&pass=${o.voucher_pass}`)
    res.redirect(`${FRONTEND_URL}/success?error=not_paid`)
  } catch (err) {
    console.error("Success redirect error:", err.message)
    res.redirect(`${FRONTEND_URL}/success?error=server_error`)
  }
})

/* ================================================================
   Routes — Admin: Server Status & Toggles
================================================================ */

app.get("/admin/server-status", auth, adminOnly, async (req, res) => {
  const toggles = getSystemToggles()
  const status = {
    mode: toggles.mode,
    mikrotik: { enabled: toggles.mikrotik, online: false },
    radius: { enabled: toggles.radius, online: false },
  }
  if (mikrotikConfig.host) {
    try { const c = await getMikrotikConnection(); c.close(); status.mikrotik.online = true } catch { }
  }
  if (radiusPool) {
    try { await radiusQuery("SELECT 1"); status.radius.online = true } catch { }
  }
  res.json(status)
})

app.put("/admin/server-mode", auth, adminOnly, (req, res) => {
  const { mode } = req.body
  if (!["mikrotik", "radius", "both"].includes(mode))
    return res.status(400).json({ error: "mode غير صحيح" })
  const toggles = getSystemToggles()
  toggles.mode = mode
  toggles.mikrotik = mode === "mikrotik" || mode === "both"
  toggles.radius = mode === "radius" || mode === "both"
  saveSystemToggles(toggles)
  // تحديث الكاش فوراً بعد تغيير الـ mode
  updateStatusCache()
  res.json({ success: true, toggles })
})

app.put("/admin/server-toggle", auth, adminOnly, (req, res) => {
  const { system, enabled } = req.body
  if (!["mikrotik", "radius"].includes(system))
    return res.status(400).json({ error: "system غير صحيح" })
  const toggles = getSystemToggles()
  toggles[system] = !!enabled
  saveSystemToggles(toggles)
  res.json({ success: true, toggles })
})

// تحكم مستقل في تفعيل/إيقاف الدفع
app.put("/admin/payments-toggle", auth, adminOnly, (req, res) => {
  const { enabled } = req.body
  const toggles = getSystemToggles()
  toggles.payments_enabled = !!enabled
  saveSystemToggles(toggles)
  res.json({ success: true, payments_enabled: toggles.payments_enabled })
})

app.get("/admin/payments-status", auth, adminOnly, (req, res) => {
  const toggles = getSystemToggles()
  res.json({
    payments_enabled: toggles.payments_enabled !== false,
    auto_paused: toggles.auto_paused === true,
    available: toggles.payments_enabled !== false && !toggles.auto_paused,
  })
})

/* ================================================================
   Routes — Admin: RADIUS Config
================================================================ */

app.get("/admin/radius/config", auth, adminOnly, (req, res) => {
  const cfg = getRadiusConfig()
  if (!cfg) return res.json({ configured: false })
  res.json({
    configured: true, host: cfg.host, port: cfg.port,
    username: cfg.username, database: cfg.database
  })
})

app.put("/admin/radius/config", auth, adminOnly, (req, res) => {
  const { host, port, username, password, database } = req.body
  if (!host || !username || !password)
    return res.status(400).json({ error: "host و username و password مطلوبين" })
  const cfg = { host, port: port || 3306, username, password, database: database || "radius" }
  fs.writeFileSync("./radius-config.json", JSON.stringify(cfg, null, 2))
  buildRadiusPool(cfg)
  res.json({ success: true, message: "تم حفظ إعدادات RADIUS بنجاح" })
})

app.post("/admin/radius/test", auth, adminOnly, async (req, res) => {
  try {
    await radiusQuery("SELECT 1")
    const [tables] = await radiusPool.query("SHOW TABLES")
    res.json({
      success: true, message: "الاتصال ناجح ✅",
      tables: tables.map(t => Object.values(t)[0])
    })
  } catch (err) {
    res.status(500).json({ success: false, error: err.message })
  }
})

/* ================================================================
   Routes — Admin: RADIUS Sessions & History
================================================================ */

app.get("/admin/radius/sessions", auth, adminOnly, async (req, res) => {
  try {
    const sessions = await getActiveSessions()
    res.json(sessions.map(s => ({
      ...s,
      duration: formatDuration(s.duration_sec),
      bytes_up: formatBytes(s.bytes_up),
      bytes_down: formatBytes(s.bytes_down),
    })))
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get("/admin/radius/history", auth, adminOnly, async (req, res) => {
  const { username, limit = 100, offset = 0 } = req.query
  try {
    const rows = username
      ? await radiusQuery(
        `SELECT * FROM radacct WHERE username = ? ORDER BY acctstarttime DESC LIMIT ? OFFSET ?`,
        [username, Number(limit), Number(offset)])
      : await radiusQuery(
        `SELECT * FROM radacct ORDER BY acctstarttime DESC LIMIT ? OFFSET ?`,
        [Number(limit), Number(offset)])
    res.json(rows)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post("/admin/radius/disconnect/:radacctid", auth, adminOnly, async (req, res) => {
  try {
    await radiusQuery(`
      UPDATE radacct
      SET acctstoptime = NOW(),
          acctterminatecause = 'Admin-Disconnect',
          acctsessiontime = TIMESTAMPDIFF(SECOND, acctstarttime, NOW())
      WHERE radacctid = ? AND acctstoptime IS NULL`,
      [req.params.radacctid])
    res.json({ success: true, message: "تم قطع الجلسة" })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

/* ================================================================
   Routes — Admin: RADIUS Users
================================================================ */

app.get("/admin/radius/users", auth, adminOnly, async (req, res) => {
  try {
    const rows = await radiusQuery(`SELECT DISTINCT username FROM radcheck ORDER BY username`)
    const users = await Promise.all(rows.map(async ({ username }) => {
      const attrs = await radiusQuery("SELECT attribute, value FROM radcheck     WHERE username = ?", [username])
      const reply = await radiusQuery("SELECT attribute, value FROM radreply     WHERE username = ?", [username])
      const groups = await radiusQuery("SELECT groupname           FROM radusergroup WHERE username = ?", [username])
      const attr = (name) => attrs.find(a => a.attribute === name)?.value || null
      const rep = (name) => reply.find(a => a.attribute === name)?.value || null
      const [active] = await radiusPool.query(
        "SELECT radacctid FROM radacct WHERE username = ? AND acctstoptime IS NULL LIMIT 1",
        [username])
      return {
        username,
        password: attr("Cleartext-Password"),
        expiry: attr("Expiration"),
        rateLimit: rep("Mikrotik-Rate-Limit"),
        groups: groups.map(g => g.groupname),
        isOnline: active.length > 0,
        isExpired: attr("Expiration") ? new Date(attr("Expiration")) < new Date() : false,
      }
    }))
    res.json(users)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post("/admin/radius/users", auth, adminOnly, async (req, res) => {
  const { username, password, planId, days, download, upload } = req.body
  if (!username || !password)
    return res.status(400).json({ error: "username و password مطلوبين" })
  try {
    let plan = { days: days || 30, download: download || "10M", upload: upload || "5M" }
    if (planId) {
      const [rows] = await db.query("SELECT * FROM plans WHERE id = ?", [planId])
      if (rows[0]) plan = rows[0]
    }
    await addRadiusUser(username, password, plan)
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.put("/admin/radius/users/:username", auth, adminOnly, async (req, res) => {
  const { username } = req.params
  const { password, expiry, rateLimit } = req.body
  try {
    if (password)
      await radiusQuery(
        `UPDATE radcheck SET value = ? WHERE username = ? AND attribute = 'Cleartext-Password'`,
        [password, username])
    if (expiry)
      await radiusQuery(
        `INSERT INTO radcheck (username, attribute, op, value) VALUES (?, 'Expiration', ':=', ?)
         ON DUPLICATE KEY UPDATE value = VALUES(value)`,
        [username, expiry])
    if (rateLimit)
      await radiusQuery(
        `INSERT INTO radreply (username, attribute, op, value) VALUES (?, 'Mikrotik-Rate-Limit', '=', ?)
         ON DUPLICATE KEY UPDATE value = VALUES(value)`,
        [username, rateLimit])
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete("/admin/radius/users/:username", auth, adminOnly, async (req, res) => {
  try {
    await deleteRadiusUser(req.params.username)
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get("/admin/radius/users/:username/sessions", auth, adminOnly, async (req, res) => {
  try {
    const sessions = await getUserSessions(req.params.username)
    res.json(sessions.map(s => ({
      ...s,
      duration: formatDuration(s.duration_sec),
      bytes_up: formatBytes(s.bytes_up),
      bytes_down: formatBytes(s.bytes_down),
    })))
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

/* ================================================================
   Routes — Admin: RADIUS Stats & NAS
================================================================ */

app.get("/admin/radius/stats", auth, adminOnly, async (req, res) => {
  try {
    const [online] = await radiusPool.query("SELECT COUNT(*) AS count FROM radacct WHERE acctstoptime IS NULL")
    const [today] = await radiusPool.query("SELECT COUNT(*) AS count FROM radacct WHERE DATE(acctstarttime) = CURDATE()")
    const [totalData] = await radiusPool.query("SELECT SUM(acctinputoctets + acctoutputoctets) AS total FROM radacct WHERE DATE(acctstarttime) = CURDATE()")
    const [topUsers] = await radiusPool.query(`
      SELECT username, COUNT(*) AS sessions, SUM(acctinputoctets + acctoutputoctets) AS total_bytes
      FROM radacct WHERE DATE(acctstarttime) = CURDATE()
      GROUP BY username ORDER BY total_bytes DESC LIMIT 10`)
    res.json({
      onlineNow: online[0].count,
      sessionsToday: today[0].count,
      dataToday: formatBytes(totalData[0].total || 0),
      topUsers: topUsers.map(u => ({
        username: u.username,
        sessions: u.sessions,
        totalData: formatBytes(u.total_bytes || 0),
      })),
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get("/admin/radius/nas", auth, adminOnly, async (req, res) => {
  try {
    res.json(await radiusQuery("SELECT * FROM nas ORDER BY nasname"))
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post("/admin/radius/nas", auth, adminOnly, async (req, res) => {
  const { nasname, shortname, secret, type, description } = req.body
  if (!nasname || !secret)
    return res.status(400).json({ error: "nasname و secret مطلوبين" })
  try {
    await radiusQuery(
      `INSERT INTO nas (nasname, shortname, secret, type, description) VALUES (?, ?, ?, ?, ?)`,
      [nasname, shortname || nasname, secret, type || "other", description || ""])
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete("/admin/radius/nas/:id", auth, adminOnly, async (req, res) => {
  try {
    await radiusQuery("DELETE FROM nas WHERE id = ?", [req.params.id])
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

/* ================================================================
   Routes — Admin: Orders & Users
================================================================ */

app.get("/admin/orders", auth, adminOnly, async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM orders ORDER BY created_at DESC")
    res.json(rows.map(o => ({
      id: o.id,
      userId: o.user_id,
      username: o.username,
      userName: o.user_name,
      planId: o.plan_id,
      planName: o.plan_name,
      amount: o.amount,
      status: o.status,
      createdAt: o.created_at,
      provider: o.provider || "mikrotik",
      voucher: o.voucher_user ? {
        username: o.voucher_user,
        password: o.voucher_pass,
        days: o.voucher_days,
        download: o.voucher_download,
        upload: o.voucher_upload,
        planName: o.plan_name,
      } : null,
    })))
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get("/admin/users", auth, adminOnly, async (req, res) => {
  try {
    const [users] = await db.query("SELECT id, username, name FROM users WHERE role != 'admin'")
    const [orders] = await db.query("SELECT * FROM orders")
    res.json(users.map(u => ({
      id: u.id,
      username: u.username,
      name: u.name,
      orders: orders.filter(o => o.user_id === u.id).map(o => ({
        id: o.id,
        planName: o.plan_name,
        amount: o.amount,
        status: o.status,
        createdAt: o.created_at,
        voucher: o.voucher_user
          ? { username: o.voucher_user, password: o.voucher_pass, planName: o.plan_name }
          : null,
      })),
    })))
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

/* ================================================================
   Routes — Admin: Plans
================================================================ */

app.post("/admin/plans", auth, adminOnly, async (req, res) => {
  const { id, name, price, days, download, upload, popular } = req.body
  if (!id || !name) return res.status(400).json({ error: "id و name مطلوبين" })
  try {
    await db.query(
      "INSERT INTO plans (id, name, price, days, download, upload, popular) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [id, name, Number(price), Number(days), download, upload, popular ? 1 : 0])
    res.json({ success: true })
  } catch (err) {
    res.status(400).json({ error: err.code === "ER_DUP_ENTRY" ? "ID موجود بالفعل" : err.message })
  }
})

app.put("/admin/plans/:id", auth, adminOnly, async (req, res) => {
  const { name, price, days, download, upload, popular } = req.body
  try {
    await db.query(
      "UPDATE plans SET name=?, price=?, days=?, download=?, upload=?, popular=? WHERE id=?",
      [name, Number(price), Number(days), download, upload, popular ? 1 : 0, req.params.id])
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete("/admin/plans/:id", auth, adminOnly, async (req, res) => {
  try {
    await db.query("DELETE FROM plans WHERE id=?", [req.params.id])
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

/* ================================================================
   Routes — Admin: Mikrotik
================================================================ */

app.get("/admin/mikrotik/config", auth, adminOnly, (req, res) => {
  res.json({ host: mikrotikConfig.host, port: mikrotikConfig.port, username: mikrotikConfig.username })
})

app.put("/admin/mikrotik/config", auth, adminOnly, (req, res) => {
  const { host, port, username, password } = req.body
  if (host) mikrotikConfig.host = host
  if (port) mikrotikConfig.port = port
  if (username) mikrotikConfig.username = username
  if (password) mikrotikConfig.password = password
  fs.writeFileSync("./mikrotik-config.json", JSON.stringify(mikrotikConfig, null, 2))
  res.json({ success: true, message: "تم حفظ إعدادات الميكروتك بنجاح" })
})

app.get("/admin/mikrotik/users", auth, adminOnly, async (req, res) => {
  try {
    const conn = await getMikrotikConnection()
    const list = await conn.write("/ip/hotspot/user/print")
    conn.close()
    res.json(list)
  } catch (err) {
    res.status(500).json({ error: "تعذر الاتصال بالميكروتيك: " + err.message })
  }
})

app.post("/admin/mikrotik/add-user", auth, adminOnly, async (req, res) => {
  const { username, password, planId, comment } = req.body
  try {
    const [plans] = await db.query("SELECT * FROM plans WHERE id=?", [planId])
    const plan = plans[0]
    const conn = await getMikrotikConnection()
    const params = [`=name=${username}`, `=password=${password}`]
    if (plan?.days) params.push(`=limit-uptime=${plan.days}d`)
    if (comment) params.push(`=comment=${comment}`)
    await conn.write(["/ip/hotspot/user/add", ...params])
    conn.close()
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.put("/admin/mikrotik/user/:name", auth, adminOnly, async (req, res) => {
  const { password, limitUptime, comment } = req.body
  try {
    const conn = await getMikrotikConnection()
    const list = await conn.write("/ip/hotspot/user/print")
    const user = list.find(u => u.name === req.params.name)
    if (!user) { conn.close(); return res.status(404).json({ error: "المستخدم مش موجود" }) }
    const params = [`=.id=${user[".id"]}`]
    if (password) params.push(`=password=${password}`)
    if (limitUptime) params.push(`=limit-uptime=${limitUptime}`)
    if (comment !== undefined) params.push(`=comment=${comment}`)
    await conn.write(["/ip/hotspot/user/set", ...params])
    conn.close()
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete("/admin/mikrotik/user/:name", auth, adminOnly, async (req, res) => {
  try {
    const conn = await getMikrotikConnection()
    const list = await conn.write("/ip/hotspot/user/print")
    const user = list.find(u => u.name === req.params.name)
    if (!user) { conn.close(); return res.status(404).json({ error: "المستخدم مش موجود" }) }
    await conn.write(["/ip/hotspot/user/remove", `=.id=${user[".id"]}`])
    conn.close()
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post("/admin/mikrotik/generate-script", auth, adminOnly, async (req, res) => {
  const { username, password, planId } = req.body
  const [plans] = await db.query("SELECT * FROM plans WHERE id=?", [planId])
  const plan = plans[0] || {}
  const script = `/ip hotspot user add name="${username}" password="${password}"` +
    (plan.days ? ` limit-uptime=${plan.days}d` : "") +
    (plan.download ? ` rate-limit="${plan.download}/${plan.upload || "5M"}"` : "") +
    ` comment="auto-generated"`
  res.json({ script })
})

app.post("/admin/mikrotik/test", auth, adminOnly, async (req, res) => {
  try {
    const conn = await getMikrotikConnection()
    conn.close()
    res.json({ success: true, message: "الاتصال ناجح ✅" })
  } catch (err) {
    res.status(500).json({ success: false, error: err.message })
  }
})

/* ================================================================
   Start
================================================================ */

app.listen(PORT, () => {
  console.log("✅ Server running on port", PORT)
})