// netlify/functions/verify-2fa.js
const OTPAuth = require("otpauth");

if (!global.USERS) global.USERS = {};

exports.handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json"
  };

  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };
  if (event.httpMethod !== "POST")    return { statusCode: 405, headers, body: JSON.stringify({ ok: false, error: "Method not allowed" }) };

  try {
    const { email, code } = JSON.parse(event.body || "{}");

    if (!email || !code) {
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Datos incompletos." }) };
    }

    const key  = email.toLowerCase().trim();
    const user = global.USERS[key];

    if (!user) {
      return { statusCode: 404, headers, body: JSON.stringify({ ok: false, error: "Usuario no encontrado." }) };
    }

    const totp = new OTPAuth.TOTP({
      issuer:    "LoginPremium",
      label:     key,
      algorithm: "SHA1",
      digits:    6,
      period:    30,
      secret:    OTPAuth.Secret.fromBase32(user.totpSecret)
    });

    const delta = totp.validate({ token: code.trim(), window: 1 });

    if (delta === null) {
      return { statusCode: 401, headers, body: JSON.stringify({ ok: false, error: "Código incorrecto o expirado." }) };
    }

    // Generar token de sesión simple
    const sessionToken = Buffer.from(JSON.stringify({
      email: key,
      name:  user.name,
      ts:    Date.now()
    })).toString("base64");

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ ok: true, token: sessionToken, name: user.name, email: key })
    };

  } catch (err) {
    console.error(err);
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: "Error interno." }) };
  }
};
