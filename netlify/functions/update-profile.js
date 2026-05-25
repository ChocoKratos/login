// netlify/functions/update-profile.js
// Lab 2 — Firma electrónica HMAC-SHA256
// Permite actualizar datos de usuario y firmar el registro resultante

const fetch  = require("node-fetch");
const crypto = require("crypto"); // nativo en Node.js, sin instalar

const JSONBIN_KEY = process.env.JSONBIN_KEY;
const JSONBIN_BIN = process.env.JSONBIN_BIN;
const SECRET_KEY  = process.env.SECRET_KEY || "clave-secreta-hmac-super-robusta-2024";
const BIN_URL     = `https://api.jsonbin.io/v3/b/${JSONBIN_BIN}`;

const headers = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json"
};

// ── Leer datos de JSONBin ──────────────────────────────────────────────────
async function getData() {
  const res  = await fetch(BIN_URL + "/latest", {
    headers: { "X-Master-Key": JSONBIN_KEY }
  });
  const json = await res.json();
  return json.record || { posts: [], users: {} };
}

// ── Guardar datos en JSONBin ──────────────────────────────────────────────
async function saveData(data) {
  await fetch(BIN_URL, {
    method:  "PUT",
    headers: { "X-Master-Key": JSONBIN_KEY, "Content-Type": "application/json" },
    body:    JSON.stringify(data)
  });
}

// ── Decodificar token de sesión ───────────────────────────────────────────
function parseToken(token) {
  try { return JSON.parse(Buffer.from(token, "base64").toString()); }
  catch(e) { return null; }
}

// ──────────────────────────────────────────────────────────────────────────
// FUNCIÓN PRINCIPAL: Generar firma HMAC-SHA256
// Combina los datos del registro con la SECRET_KEY
// Devuelve exactamente 64 caracteres en hexadecimal
// ──────────────────────────────────────────────────────────────────────────
function generateSignature(data) {
  // Serializar los datos en orden fijo para que la firma sea determinista
  const payload = JSON.stringify({
    email:     data.email,
    name:      data.name,
    role:      data.role,
    balance:   data.balance,
    updatedAt: data.updatedAt
  });

  // HMAC-SHA256 con la clave secreta del servidor
  const signature = crypto
    .createHmac("sha256", SECRET_KEY)
    .update(payload)
    .digest("hex"); // 64 caracteres hexadecimales

  console.log(`SIGNATURE generated (${signature.length} chars):`, signature);
  return signature;
}

// ──────────────────────────────────────────────────────────────────────────
// FUNCIÓN DE VERIFICACIÓN
// Lee los datos y comprueba si la firma guardada coincide
// Si alguien alteró los datos en la BD sin conocer SECRET_KEY → falla
// ──────────────────────────────────────────────────────────────────────────
function verifySignature(record) {
  if (!record.signature) return { valid: false, reason: "Sin firma registrada" };

  const expectedSignature = generateSignature(record);

  const valid = crypto.timingSafeEqual(
    Buffer.from(record.signature,   "hex"),
    Buffer.from(expectedSignature,  "hex")
  );

  return {
    valid,
    reason: valid
      ? "Firma válida — datos íntegros"
      : "⚠️ FIRMA INVÁLIDA — datos fueron alterados sin autorización"
  };
}

// ──────────────────────────────────────────────────────────────────────────
// HANDLER PRINCIPAL
// ──────────────────────────────────────────────────────────────────────────
exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };

  // ── GET: verificar integridad del registro actual ──
  if (event.httpMethod === "GET") {
    const token = event.queryStringParameters?.token;
    const session = parseToken(token);
    if (!session) return { statusCode: 401, headers, body: JSON.stringify({ ok: false, error: "Sesión inválida." }) };

    const data = await getData();
    const user = data.users?.[session.email];
    if (!user) return { statusCode: 404, headers, body: JSON.stringify({ ok: false, error: "Usuario no encontrado." }) };

    const verification = verifySignature(user);

    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        ok: true,
        user: {
          email:     user.email,
          name:      user.name,
          role:      user.role      || "user",
          balance:   user.balance   ?? 0,
          updatedAt: user.updatedAt || user.createdAt,
          signature: user.signature || null
        },
        verification
      })
    };
  }

  // ── POST: actualizar registro y generar nueva firma ──
  if (event.httpMethod === "POST") {
    try {
      const { token, name, role, balance } = JSON.parse(event.body || "{}");

      const session = parseToken(token);
      if (!session) return { statusCode: 401, headers, body: JSON.stringify({ ok: false, error: "Sesión inválida." }) };

      // Validar longitud mínima del nombre (simula el requisito de 20 chars)
      if (!name || name.trim().length < 20)
        return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "El nombre debe tener al menos 20 caracteres para la firma." }) };

      const data = await getData();
      if (!data.users) data.users = {};

      const user = data.users[session.email];
      if (!user) return { statusCode: 404, headers, body: JSON.stringify({ ok: false, error: "Usuario no encontrado." }) };

      // ── SIMULACIÓN UPDATE ──
      // Guardar estado anterior para mostrar en la respuesta
      const previousRecord = {
        name:      user.name,
        role:      user.role    || "user",
        balance:   user.balance ?? 0,
        signature: user.signature || null
      };

      // Aplicar cambios
      user.name      = name.trim();
      user.role      = role    || user.role    || "user";
      user.balance   = balance ?? user.balance ?? 0;
      user.updatedAt = new Date().toISOString();

      // Generar nueva firma con los datos actualizados
      user.signature = generateSignature(user);

      // Guardar en JSONBin
      data.users[session.email] = user;
      await saveData(data);

      // Verificar inmediatamente para confirmar integridad
      const verification = verifySignature(user);

      return {
        statusCode: 200, headers,
        body: JSON.stringify({
          ok: true,
          message:  "Registro actualizado y firmado correctamente",
          previous: previousRecord,
          updated: {
            email:     user.email,
            name:      user.name,
            role:      user.role,
            balance:   user.balance,
            updatedAt: user.updatedAt,
            signature: user.signature,
            signatureLength: user.signature.length
          },
          verification
        })
      };

    } catch(err) {
      console.error("UPDATE error:", err.message);
      return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: "Error interno: " + err.message }) };
    }
  }

  return { statusCode: 405, headers, body: JSON.stringify({ ok: false, error: "Method not allowed" }) };
};
