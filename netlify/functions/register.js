const fetch   = require("node-fetch");
const OTPAuth = require("otpauth");
const QRCode  = require("qrcode");

const JSONBIN_KEY = process.env.JSONBIN_KEY;
const JSONBIN_BIN = process.env.JSONBIN_BIN;
const BIN_URL     = `https://api.jsonbin.io/v3/b/${JSONBIN_BIN}`;

const headers = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json"
};

async function getData() {
  const res  = await fetch(BIN_URL + "/latest", { headers: { "X-Master-Key": JSONBIN_KEY } });
  const json = await res.json();
  console.log("getData status:", res.status);
  return json.record || { posts: [], users: {} };
}

async function saveData(data) {
  const res = await fetch(BIN_URL, {
    method: "PUT",
    headers: { "X-Master-Key": JSONBIN_KEY, "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });
  const json = await res.json();
  console.log("saveData status:", res.status, JSON.stringify(json).slice(0,200));
  return res.status;
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validateDate(dateStr) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return false;
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return false;
  const today = new Date();
  const age   = today.getFullYear() - d.getFullYear();
  const m     = today.getMonth() - d.getMonth();
  return age > 18 || (age === 18 && (m > 0 || (m === 0 && today.getDate() >= d.getDate())));
}

function validatePassword(pass) {
  return /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/.test(pass);
}

function validateCedula(cedula) {
  const nacional   = /^[1-9]-\d+-\d+$/;
  const extranjero = /^E-\d+-\d+$/;
  const pasaporte  = /^PE-\d+-\d+$/;
  return nacional.test(cedula) || extranjero.test(cedula) || pasaporte.test(cedula);
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };
  if (event.httpMethod !== "POST")    return { statusCode: 405, headers, body: JSON.stringify({ ok: false, error: "Method not allowed" }) };

  try {
    const {
      firstName, lastName, email, birthDate,
      cedula, password, confirmPassword,
      photoName, cedulaDocName, initialBalance
      // NOTA: NO recibimos las fotos en base64 aquí
      // Se guardan en localStorage del navegador para no superar el límite de JSONBin
    } = JSON.parse(event.body || "{}");

    console.log("REGISTER attempt:", email);

    if (!firstName || !lastName || !email || !birthDate || !cedula || !password || !confirmPassword)
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Todos los campos son obligatorios." }) };

    if (!validateEmail(email))
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Formato de correo electrónico inválido." }) };

    if (!validateDate(birthDate))
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Fecha inválida. Debes ser mayor de 18 años." }) };

    if (!validateCedula(cedula.toUpperCase()))
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Cédula inválida. Ej: 8-123-4567 / E-123-456 / PE-12-3456" }) };

    if (!validatePassword(password))
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "La contraseña debe tener mínimo 8 caracteres, una mayúscula, un número y un carácter especial." }) };

    if (password !== confirmPassword)
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Las contraseñas no coinciden." }) };

    const data = await getData();
    if (!data.users) data.users = {};
    if (!data.posts)  data.posts  = [];

    const key = email.toLowerCase().trim();

    if (data.users[key])
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Este correo ya está registrado." }) };

    const cedulaUpper = cedula.toUpperCase().trim();
    const cedulaExists = Object.values(data.users).some(u => u.cedula === cedulaUpper);
    if (cedulaExists)
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Esta cédula ya está registrada." }) };

    // Crear TOTP
    const secret = new OTPAuth.Secret();
    const totp   = new OTPAuth.TOTP({
      issuer: "LoginPremium", label: key,
      algorithm: "SHA1", digits: 6, period: 30, secret
    });
    const qrDataURL = await QRCode.toDataURL(totp.toString());

    const balance = Math.max(0, parseFloat(initialBalance) || 0);

    // Guardar solo metadatos en JSONBin (sin fotos base64)
    data.users[key] = {
      firstName:    firstName.trim(),
      lastName:     lastName.trim(),
      name:         `${firstName.trim()} ${lastName.trim()}`,
      email:        key,
      birthDate,
      cedula:       cedulaUpper,
      password,
      photoName:    photoName || "",    // solo nombre del archivo
      cedulaDocName: cedulaDocName || "",
      totpSecret:   secret.base32,
      role:         "user",
      balance,
      transactions: [],
      createdAt:    new Date().toISOString(),
      updatedAt:    new Date().toISOString()
    };

    const saveStatus = await saveData(data);
    console.log("Saved user:", key, "status:", saveStatus);

    return {
      statusCode: 200, headers,
      body: JSON.stringify({ ok: true, email: key, name: data.users[key].name, qr: qrDataURL, secret: secret.base32 })
    };

  } catch(err) {
    console.error("REGISTER error:", err.message);
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: "Error interno: " + err.message }) };
  }
};
