const fetch   = require("node-fetch");
const OTPAuth = require("otpauth");
const QRCode  = require("qrcode");

const HCAPTCHA_SECRET = process.env.HCAPTCHA_SECRET;
const JSONBIN_KEY     = process.env.JSONBIN_KEY;
const JSONBIN_BIN     = process.env.JSONBIN_BIN;
const BIN_URL         = `https://api.jsonbin.io/v3/b/${JSONBIN_BIN}`;

const headers = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json"
};

async function getData() {
  const res  = await fetch(BIN_URL + "/latest", { headers: { "X-Master-Key": JSONBIN_KEY } });
  const json = await res.json();
  return json.record || { posts: [], users: {} };
}

async function saveData(data) {
  await fetch(BIN_URL, {
    method: "PUT",
    headers: { "X-Master-Key": JSONBIN_KEY, "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });
}

async function verifyCaptcha(token) {
  if (!token) return false;
  const res  = await fetch("https://hcaptcha.com/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `secret=${HCAPTCHA_SECRET}&response=${token}`
  });
  const data = await res.json();
  return data.success === true;
}

// ── Validaciones ──────────────────────────────────────────────────────────
function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validateDate(dateStr) {
  // Formato YYYY-MM-DD y que sea fecha real
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return false;
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return false;
  // Mayor de 18 años
  const today = new Date();
  const age   = today.getFullYear() - d.getFullYear();
  const m     = today.getMonth() - d.getMonth();
  const ageOk = age > 18 || (age === 18 && (m > 0 || (m === 0 && today.getDate() >= d.getDate())));
  return ageOk;
}

function validatePassword(pass) {
  // Mínimo 8 chars, 1 mayúscula, 1 número, 1 especial
  return /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/.test(pass);
}

function validateCedula(cedula) {
  // Formato cédula panameña
  // Nacional:   X-XXX-XXXX  (provincia 1-9, tomo, asiento)
  // Extranjero: E-XXX-XXXX
  // Pasaporte:  PE-XX-XXXX
  const nacional   = /^[1-9]-\d{1,4}-\d{1,6}$/;
  const extranjero = /^E-\d{1,4}-\d{1,6}$/;
  const pasaporte  = /^PE-\d{1,4}-\d{1,6}$/;
  return nacional.test(cedula) || extranjero.test(cedula) || pasaporte.test(cedula);
}

// ── Validar base64 de imagen (JPG/PNG máx 2MB) ───────────────────────────
function validatePhoto(base64) {
  if (!base64) return { ok: false, error: "Foto de perfil requerida." };
  const isJpg = base64.startsWith("data:image/jpeg") || base64.startsWith("data:image/jpg");
  const isPng = base64.startsWith("data:image/png");
  if (!isJpg && !isPng) return { ok: false, error: "La foto debe ser JPG o PNG." };
  // Calcular tamaño aproximado en bytes
  const base64Data = base64.split(",")[1] || "";
  const sizeBytes  = Math.ceil(base64Data.length * 0.75);
  if (sizeBytes > 2 * 1024 * 1024) return { ok: false, error: "La foto no puede superar 2MB." };
  return { ok: true };
}

// ── Validar base64 de PDF (máx 5MB) ──────────────────────────────────────
function validatePDF(base64) {
  if (!base64) return { ok: false, error: "PDF de cédula requerido." };
  if (!base64.startsWith("data:application/pdf")) return { ok: false, error: "El documento debe ser un PDF." };
  const base64Data = base64.split(",")[1] || "";
  const sizeBytes  = Math.ceil(base64Data.length * 0.75);
  if (sizeBytes > 5 * 1024 * 1024) return { ok: false, error: "El PDF no puede superar 5MB." };
  return { ok: true };
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };
  if (event.httpMethod !== "POST")    return { statusCode: 405, headers, body: JSON.stringify({ ok: false, error: "Method not allowed" }) };

  try {
    const {
      firstName, lastName, email, birthDate,
      cedula, password, confirmPassword,
      photo, cedulaPDF, captchaToken
    } = JSON.parse(event.body || "{}");

    // ── Validaciones de campos requeridos ──
    if (!firstName || !lastName || !email || !birthDate || !cedula || !password || !confirmPassword || !captchaToken)
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Todos los campos son obligatorios." }) };

    if (!validateEmail(email))
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Formato de correo electrónico inválido." }) };

    if (!validateDate(birthDate))
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Fecha de nacimiento inválida. Debes ser mayor de 18 años." }) };

    if (!validateCedula(cedula))
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Cédula inválida. Formato: 8-123-4567 (nacional) o E-123-4567 / PE-12-3456 (extranjero)." }) };

    if (!validatePassword(password))
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "La contraseña debe tener mínimo 8 caracteres, una mayúscula, un número y un carácter especial." }) };

    if (password !== confirmPassword)
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Las contraseñas no coinciden." }) };

    // ── Validar archivos ──
    const photoCheck = validatePhoto(photo);
    if (!photoCheck.ok) return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: photoCheck.error }) };

    const pdfCheck = validatePDF(cedulaPDF);
    if (!pdfCheck.ok) return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: pdfCheck.error }) };

    // ── Verificar captcha ──
    const captchaOk = await verifyCaptcha(captchaToken);
    if (!captchaOk)
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Captcha inválido." }) };

    const key  = email.toLowerCase().trim();
    const data = await getData();
    if (!data.users) data.users = {};
    if (!data.posts)  data.posts = [];

    if (data.users[key])
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Este correo ya está registrado." }) };

    // Verificar cédula única
    const cedulaExists = Object.values(data.users).some(u => u.cedula === cedula);
    if (cedulaExists)
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Esta cédula ya está registrada." }) };

    // ── Crear TOTP ──
    const secret = new OTPAuth.Secret();
    const totp   = new OTPAuth.TOTP({
      issuer: "LoginPremium", label: key,
      algorithm: "SHA1", digits: 6, period: 30, secret
    });
    const qrDataURL = await QRCode.toDataURL(totp.toString());

    // ── Guardar usuario ──
    data.users[key] = {
      firstName:  firstName.trim(),
      lastName:   lastName.trim(),
      name:       `${firstName.trim()} ${lastName.trim()}`,
      email:      key,
      birthDate,
      cedula,
      password,
      photo,       // base64 JPG/PNG
      cedulaPDF,   // base64 PDF
      totpSecret:  secret.base32,
      role:        "user",
      balance:     0,
      createdAt:   new Date().toISOString(),
      updatedAt:   new Date().toISOString()
    };

    await saveData(data);

    return {
      statusCode: 200, headers,
      body: JSON.stringify({ ok: true, email: key, name: data.users[key].name, qr: qrDataURL, secret: secret.base32 })
    };

  } catch(err) {
    console.error("REGISTER error:", err.message);
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: "Error interno: " + err.message }) };
  }
};
