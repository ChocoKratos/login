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
  if (!token) { console.log("CAPTCHA: token vacío"); return false; }
  const res  = await fetch("https://hcaptcha.com/siteverify", {
    method:  "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body:    `secret=${HCAPTCHA_SECRET}&response=${token}`
  });
  const data = await res.json();
  console.log("CAPTCHA result:", JSON.stringify(data));
  return data.success === true;
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };
  if (event.httpMethod !== "POST")    return { statusCode: 405, headers, body: JSON.stringify({ ok: false, error: "Method not allowed" }) };

  try {
    const body = JSON.parse(event.body || "{}");
    const { email, password, captchaToken } = body;

    console.log("LOGIN attempt:", email);
    console.log("Has captcha token:", !!captchaToken);
    console.log("HCAPTCHA_SECRET set:", !!HCAPTCHA_SECRET);
    console.log("JSONBIN_KEY set:", !!JSONBIN_KEY);
    console.log("JSONBIN_BIN set:", !!JSONBIN_BIN);

    if (!email || !password || !captchaToken)
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Completa todos los campos." }) };

    const captchaOk = await verifyCaptcha(captchaToken);
    if (!captchaOk)
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Captcha inválido. Intenta de nuevo." }) };

    const key  = email.toLowerCase().trim();
    const data = await getUsers();

    console.log("Users found:", Object.keys(data.users || {}).length);

    const user = data.users && data.users[key];

    if (!user)
      return { statusCode: 401, headers, body: JSON.stringify({ ok: false, error: "Email o contraseña incorrectos." }) };

    if (user.password !== password)
      return { statusCode: 401, headers, body: JSON.stringify({ ok: false, error: "Email o contraseña incorrectos." }) };

    console.log("LOGIN success:", key);

    return {
      statusCode: 200, headers,
      body: JSON.stringify({ ok: true, email: key, name: user.name, step: "2fa" })
    };

  } catch(err) {
    console.error("LOGIN error:", err.message);
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: "Error interno: " + err.message }) };
  }
};