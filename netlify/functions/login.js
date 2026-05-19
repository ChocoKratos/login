const fetch = require("node-fetch");

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
    const { email, password, captchaToken } = JSON.parse(event.body || "{}");

    if (!email || !password || !captchaToken)
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Completa todos los campos." }) };

    const captchaOk = await verifyCaptcha(captchaToken);
    if (!captchaOk)
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Captcha inválido." }) };

    const key  = email.toLowerCase().trim();
    const data = await getUsers();
    const user = data.users && data.users[key];

    if (!user || user.password !== password)
      return { statusCode: 401, headers, body: JSON.stringify({ ok: false, error: "Email o contraseña incorrectos." }) };

    return {
      statusCode: 200, headers,
      body: JSON.stringify({ ok: true, email: key, name: user.name, step: "2fa" })
    };

  } catch(err) {
    console.error(err);
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: "Error interno." }) };
  }
};
