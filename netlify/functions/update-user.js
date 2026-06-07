const fetch = require("node-fetch");

const JSONBIN_KEY = process.env.JSONBIN_KEY;
const JSONBIN_BIN = process.env.JSONBIN_BIN;
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
    const body = JSON.parse(event.body || "{}");
    const { token, firstName, lastName, phone, cedula, birthDate, balance } = body;

    const session = parseToken(token);
    if (!session)
      return { statusCode: 401, headers, body: JSON.stringify({ ok: false, error: "Sesion invalida." }) };

    const data = await getData();
    if (!data.users) data.users = {};

    const user = data.users[session.email];
    if (!user)
      return { statusCode: 404, headers, body: JSON.stringify({ ok: false, error: "Usuario no encontrado." }) };

    // Actualizar SOLO si el campo viene con valor real (no vacío)
    if (firstName && firstName.trim()) user.firstName = firstName.trim();
    if (lastName  && lastName.trim())  user.lastName  = lastName.trim();
    if (phone     && phone.trim())     user.phone     = phone.trim();
    if (cedula    && cedula.trim())    user.cedula    = cedula.trim().toUpperCase();
    if (birthDate && birthDate)        user.birthDate = birthDate;
    if (balance   !== undefined && balance !== "")
      user.balance = Math.max(0, parseFloat(balance) || 0);

    // Reconstruir nombre completo si cambió nombre o apellido
    if ((firstName && firstName.trim()) || (lastName && lastName.trim())) {
      user.name = ((user.firstName || "") + " " + (user.lastName || "")).trim();
    }

    user.updatedAt = new Date().toISOString();

    // IMPORTANTE: NO tocar firma ni transacciones — solo actualizar datos personales
    data.users[session.email] = user;
    await saveData(data);

    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        ok:      true,
        message: "Perfil actualizado correctamente",
        user: {
          firstName:    user.firstName    || "",
          lastName:     user.lastName     || "",
          name:         user.name         || "",
          phone:        user.phone        || "",
          cedula:       user.cedula       || "",
          birthDate:    user.birthDate    || "",
          balance:      user.balance      ?? 0,
          email:        user.email        || "",
          transactions: user.transactions || []
        }
      })
    };

  } catch(err) {
    console.error("update-user error:", err.message);
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: "Error: " + err.message }) };
  }
};
