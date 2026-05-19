const fetch   = require("node-fetch");
const OTPAuth = require("otpauth");

const JSONBIN_KEY = process.env.JSONBIN_KEY;
const JSONBIN_BIN = process.env.JSONBIN_BIN;
const BIN_URL     = `https://api.jsonbin.io/v3/b/${JSONBIN_BIN}`;

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

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };
  if (event.httpMethod !== "POST")    return { statusCode: 405, headers, body: JSON.stringify({ ok: false, error: "Method not allowed" }) };

  try {
    const { email, code } = JSON.parse(event.body || "{}");

    if (!email || !code)
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Datos incompletos." }) };

    const key  = email.toLowerCase().trim();
    const data = await getUsers();
    const user = data.users && data.users[key];

    if (!user)
      return { statusCode: 404, headers, body: JSON.stringify({ ok: false, error: "Usuario no encontrado." }) };

    const totp  = new OTPAuth.TOTP({
      issuer: "LoginPremium", label: key,
      algorithm: "SHA1", digits: 6, period: 30,
      secret: OTPAuth.Secret.fromBase32(user.totpSecret)
    });

    const delta = totp.validate({ token: code.trim(), window: 1 });

    if (delta === null)
      return { statusCode: 401, headers, body: JSON.stringify({ ok: false, error: "Código incorrecto o expirado." }) };

    const sessionToken = Buffer.from(JSON.stringify({
      email: key, name: user.name, ts: Date.now()
    })).toString("base64");

    return {
      statusCode: 200, headers,
      body: JSON.stringify({ ok: true, token: sessionToken, name: user.name, email: key })
    };

  } catch(err) {
    console.error(err);
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: "Error interno." }) };
  }
};
