// netlify/functions/register.js
const fetch  = require("node-fetch");
const OTPAuth = require("otpauth");
const QRCode  = require("qrcode");

const HCAPTCHA_SECRET = process.env.HCAPTCHA_SECRET;
const HCAPTCHA_URL    = "https://hcaptcha.com/siteverify";

// Almacén en memoria (se resetea al redeploy — válido para demo)
// Para producción real usar Netlify Blobs o FaunaDB
if (!global.USERS) global.USERS = {};

async function verifyCaptcha(token) {
  const res = await fetch(HCAPTCHA_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body:    `secret=${HCAPTCHA_SECRET}&response=${token}`
  });
  const data = await res.json();
  return data.success === true;
}

exports.handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json"
  };

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers, body: "" };
  }
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, headers, body: JSON.stringify({ ok: false, error: "Method not allowed" }) };
  }

  try {
    const { name, email, password, captchaToken } = JSON.parse(event.body || "{}");

    // Validaciones
    if (!name || !email || !password || !captchaToken) {
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Todos los campos son obligatorios." }) };
    }

    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRe.test(email)) {
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Email inválido." }) };
    }

    if (password.length < 8) {
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "La contraseña debe tener al menos 8 caracteres." }) };
    }

    // Verificar captcha
    const captchaOk = await verifyCaptcha(captchaToken);
    if (!captchaOk) {
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Captcha inválido. Intenta de nuevo." }) };
    }

    const key = email.toLowerCase().trim();

    if (global.USERS[key]) {
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Este email ya está registrado." }) };
    }

    // Crear secreto TOTP
    const secret = new OTPAuth.Secret();
    const totp   = new OTPAuth.TOTP({
      issuer:    "LoginPremium",
      label:     key,
      algorithm: "SHA1",
      digits:    6,
      period:    30,
      secret
    });

    // Generar QR
    const qrDataURL = await QRCode.toDataURL(totp.toString());

    // Guardar usuario (password en texto plano — solo demo)
    global.USERS[key] = {
      name:       name.trim(),
      email:      key,
      password,
      totpSecret: secret.base32,
      createdAt:  new Date().toISOString()
    };

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        ok:    true,
        email: key,
        name:  name.trim(),
        qr:    qrDataURL,
        secret: secret.base32   // para configurar manualmente si falla el QR
      })
    };

  } catch (err) {
    console.error(err);
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: "Error interno." }) };
  }
};
