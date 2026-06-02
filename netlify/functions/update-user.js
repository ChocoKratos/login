// netlify/functions/update-user.js
// Permite al usuario actualizar sus datos de perfil

const fetch  = require("node-fetch");
const crypto = require("crypto");

const JSONBIN_KEY = process.env.JSONBIN_KEY;
const JSONBIN_BIN = process.env.JSONBIN_BIN;
const SECRET_KEY  = process.env.SECRET_KEY || "clave-secreta-hmac-2024";
const BIN_URL     = "https://api.jsonbin.io/v3/b/" + JSONBIN_BIN;

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
  const res = await fetch(BIN_URL, {
    method: "PUT",
    headers: { "X-Master-Key": JSONBIN_KEY, "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });
  console.log("update-user saveData:", res.status);
}

function parseToken(token) {
  try { return JSON.parse(Buffer.from(token, "base64").toString()); }
  catch(e) { return null; }
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };
  if (event.httpMethod !== "POST")
    return { statusCode: 405, headers, body: JSON.stringify({ ok: false, error: "Method not allowed" }) };

  try {
    const { token, firstName, lastName, phone, cedula, birthDate, balance } = JSON.parse(event.body || "{}");

    const session = parseToken(token);
    if (!session) return { statusCode: 401, headers, body: JSON.stringify({ ok: false, error: "Sesion invalida." }) };

    const data = await getData();
    if (!data.users) data.users = {};

    const user = data.users[session.email];
    if (!user) return { statusCode: 404, headers, body: JSON.stringify({ ok: false, error: "Usuario no encontrado." }) };

    // Actualizar solo campos que vengan en el request
    if (firstName !== undefined && firstName.trim())  user.firstName = firstName.trim();
    if (lastName  !== undefined && lastName.trim())   user.lastName  = lastName.trim();
    if (phone     !== undefined && phone.trim())      user.phone     = phone.trim();
    if (cedula    !== undefined && cedula.trim())     user.cedula    = cedula.trim().toUpperCase();
    if (birthDate !== undefined && birthDate)         user.birthDate = birthDate;
    if (balance   !== undefined)                      user.balance   = Math.max(0, parseFloat(balance) || 0);

    // Reconstruir nombre completo
    if (firstName !== undefined || lastName !== undefined) {
      user.name = (user.firstName || '') + ' ' + (user.lastName || '');
      user.name = user.name.trim();
    }

    user.updatedAt = new Date().toISOString();

    // Nota: NO regenerar firma aquí para no invalidar la del Lab 2
    // La firma se regenera solo en el Lab 2

    data.users[session.email] = user;
    await saveData(data);

    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        ok:   true,
        message: "Perfil actualizado correctamente",
        user: {
          firstName: user.firstName || "",
          lastName:  user.lastName  || "",
          name:      user.name      || "",
          phone:     user.phone     || "",
          cedula:    user.cedula    || "",
          birthDate: user.birthDate || "",
          balance:   user.balance   || 0,
          email:     user.email
        }
      })
    };

  } catch(err) {
    console.error("update-user error:", err.message);
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: "Error interno: " + err.message }) };
  }
};
