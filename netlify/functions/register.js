const fetch   = require("node-fetch");
const OTPAuth = require("otpauth");
const QRCode  = require("qrcode");

const HCAPTCHA_SECRET = process.env.HCAPTCHA_SECRET;
const JSONBIN_KEY     = process.env.JSONBIN_KEY;
const JSONBIN_BIN     = process.env.JSONBIN_BIN;
const BIN_URL         = `https://api.jsonbin.io/v3/b/${JSONBIN_BIN}`;

const headers = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json"
};

async function getUsers() {
  const res  = await fetch(BIN_URL + "/latest", {
    headers: { "X-Master-Key": JSONBIN_KEY }
  });
  const json = await res.json();
  return json.record || { posts: [], users: {} };
}

async function saveData(data) {
  await fetch(BIN_URL, {
    method:  "PUT",
    headers: { "X-Master-Key": JSONBIN_KEY, "Content-Type": "application/json" },
    body:    JSON.stringify(data)
  });
}

async function verifyCaptcha(token) {
  if (!token) return false;
  const res  = await fetch("https://hcaptcha.com/siteverify", {
    method:  "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body:    `secret=${HCAPTCHA_SECRET}&response=${token}`
  });
  const data = await res.json();
  return data.success === true;
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };
  if (event.httpMethod !== "POST")    return { statusCode: 405, headers, body: JSON.stringify({ ok: false, error: "Method not allowed" }) };

  try {
    const { name, email, password, captchaToken } = JSON.parse(event.body || "{}");

    if (!name || !email || !password || !captchaToken)
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Todos los campos son obligatorios." }) };

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Email inválido." }) };

    if (password.length < 8)
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "La contraseña debe tener al menos 8 caracteres." }) };

    const captchaOk = await verifyCaptcha(captchaToken);
    if (!captchaOk)
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Captcha inválido." }) };

    const key  = email.toLowerCase().trim();
    const data = await getUsers();

    if (!data.users) data.users = {};
    if (!data.posts)  data.posts  = [];

    if (data.users[key])
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Este email ya está registrado." }) };

    // Crear TOTP
    const secret = new OTPAuth.Secret();
    const totp   = new OTPAuth.TOTP({
      issuer: "LoginPremium", label: key,
      algorithm: "SHA1", digits: 6, period: 30, secret
    });

    const qrDataURL = await QRCode.toDataURL(totp.toString());

    data.users[key] = {
      name:       name.trim(),
      email:      key,
      password,
      totpSecret: secret.base32,
      createdAt:  new Date().toISOString()
    };

    await saveData(data);

    return {
      statusCode: 200, headers,
      body: JSON.stringify({ ok: true, email: key, name: name.trim(), qr: qrDataURL, secret: secret.base32 })
    };

  } catch(err) {
    console.error(err);
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: "Error interno." }) };
  }
};
