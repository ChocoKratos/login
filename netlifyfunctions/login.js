// netlify/functions/login.js
const fetch   = require("node-fetch");
const OTPAuth = require("otpauth");

const HCAPTCHA_SECRET = process.env.HCAPTCHA_SECRET;
const HCAPTCHA_URL    = "https://hcaptcha.com/siteverify";

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

  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };
  if (event.httpMethod !== "POST")    return { statusCode: 405, headers, body: JSON.stringify({ ok: false, error: "Method not allowed" }) };

  try {
    const { email, password, captchaToken } = JSON.parse(event.body || "{}");

    if (!email || !password || !captchaToken) {
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Completa todos los campos." }) };
    }

    // Verificar captcha
    const captchaOk = await verifyCaptcha(captchaToken);
    if (!captchaOk) {
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Captcha inválido. Intenta de nuevo." }) };
    }

    const key  = email.toLowerCase().trim();
    const user = global.USERS[key];

    if (!user || user.password !== password) {
      return { statusCode: 401, headers, body: JSON.stringify({ ok: false, error: "Email o contraseña incorrectos." }) };
    }

    // Login OK — pedir código 2FA
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ ok: true, email: key, name: user.name, step: "2fa" })
    };

  } catch (err) {
    console.error(err);
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: "Error interno." }) };
  }
};
