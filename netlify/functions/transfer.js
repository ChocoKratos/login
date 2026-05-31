const fetch  = require("node-fetch");
const crypto = require("crypto");

const JSONBIN_KEY = process.env.JSONBIN_KEY;
const JSONBIN_BIN = process.env.JSONBIN_BIN;
const SECRET_KEY  = process.env.SECRET_KEY || "clave-secreta-hmac-2024";
const BIN_URL     = `https://api.jsonbin.io/v3/b/${JSONBIN_BIN}`;

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
  await fetch(BIN_URL, {
    method: "PUT",
    headers: { "X-Master-Key": JSONBIN_KEY, "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });
}

function parseToken(token) {
  try { return JSON.parse(Buffer.from(token, "base64").toString()); }
  catch(e) { return null; }
}

function signRecord(record) {
  const payload = JSON.stringify({
    email: record.email, name: record.name,
    role: record.role, balance: record.balance, updatedAt: record.updatedAt
  });
  return crypto.createHmac("sha256", SECRET_KEY).update(payload).digest("hex");
}

// Buscar usuario por email o nombre
function searchUser(users, query) {
  const q = query.toLowerCase().trim();
  return Object.values(users).find(u =>
    u.email.toLowerCase().includes(q) ||
    u.name.toLowerCase().includes(q)
  );
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };

  // ── GET: buscar usuario destinatario ──
  if (event.httpMethod === "GET") {
    const { token, query } = event.queryStringParameters || {};
    const session = parseToken(token);
    if (!session) return { statusCode: 401, headers, body: JSON.stringify({ ok: false, error: "Sesión inválida." }) };
    if (!query || query.length < 2) return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Ingresa al menos 2 caracteres." }) };

    const data = await getData();
    const found = searchUser(data.users || {}, query);

    if (!found || found.email === session.email)
      return { statusCode: 404, headers, body: JSON.stringify({ ok: false, error: "Usuario no encontrado." }) };

    return {
      statusCode: 200, headers,
      body: JSON.stringify({ ok: true, user: { name: found.name, email: found.email, role: found.role } })
    };
  }

  // ── POST: ejecutar transacción ──
  if (event.httpMethod === "POST") {
    try {
      const { token, type, amount, toEmail, description } = JSON.parse(event.body || "{}");

      const session = parseToken(token);
      if (!session) return { statusCode: 401, headers, body: JSON.stringify({ ok: false, error: "Sesión inválida." }) };

      const amt = parseFloat(amount);
      if (!amt || amt <= 0) return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "El monto debe ser mayor a 0." }) };
      if (!["transfer","deposit","withdraw"].includes(type))
        return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Tipo de transacción inválido." }) };

      const data = await getData();
      if (!data.users) data.users = {};

      const fromUser = data.users[session.email];
      if (!fromUser) return { statusCode: 404, headers, body: JSON.stringify({ ok: false, error: "Usuario no encontrado." }) };

      // ── Verificar firma para transferencias ──
      if (type === "transfer") {
        if (!fromUser.signature) {
          return { statusCode: 403, headers, body: JSON.stringify({
            ok: false,
            error: "Necesitas crear tu firma digital antes de transferir.",
            requiresSignature: true
          })};
        }
        // Verificar que la firma sea válida (no alterada)
        const crypto = require("crypto");
        const SECRET_KEY = process.env.SECRET_KEY || "clave-secreta-hmac-2024";
        const payload = JSON.stringify({
          email: fromUser.email, name: fromUser.name,
          role: fromUser.role, balance: fromUser.balance, updatedAt: fromUser.updatedAt
        });
        const expectedSig = crypto.createHmac("sha256", SECRET_KEY).update(payload).digest("hex");
        let sigValid = false;
        try {
          sigValid = crypto.timingSafeEqual(
            Buffer.from(fromUser.signature, "hex"),
            Buffer.from(expectedSig, "hex")
          );
        } catch(e) { sigValid = false; }

        if (!sigValid) {
          return { statusCode: 403, headers, body: JSON.stringify({
            ok: false,
            error: "Tu firma digital es inválida. Ve al Lab 2 y regenera tu firma.",
            requiresSignature: true
          })};
        }
      }

      const now = new Date().toISOString();
      const txId = \`TX-\${Date.now()}\`;

      if (type === "transfer") {
        if (!toEmail) return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Destinatario requerido." }) };
        const toUser = data.users[toEmail.toLowerCase()];
        if (!toUser) return { statusCode: 404, headers, body: JSON.stringify({ ok: false, error: "Usuario destinatario no encontrado." }) };
        if (toUser.email === session.email) return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "No puedes transferirte a ti mismo." }) };
        if (fromUser.balance < amt) return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: `Saldo insuficiente. Disponible: $${fromUser.balance.toFixed(2)}` }) };

        // Ejecutar transferencia
        fromUser.balance  = parseFloat((fromUser.balance - amt).toFixed(2));
        toUser.balance    = parseFloat((toUser.balance   + amt).toFixed(2));
        fromUser.updatedAt = now;
        toUser.updatedAt   = now;

        // Registrar transacciones
        if (!fromUser.transactions) fromUser.transactions = [];
        if (!toUser.transactions)   toUser.transactions   = [];

        fromUser.transactions.unshift({ id: txId, type: "transfer_out", amount: amt, to: toUser.email, toName: toUser.name, description: description || "", date: now });
        toUser.transactions.unshift({   id: txId, type: "transfer_in",  amount: amt, from: session.email, fromName: fromUser.name, description: description || "", date: now });

        // Mantener máximo 50 transacciones por usuario
        if (fromUser.transactions.length > 50) fromUser.transactions = fromUser.transactions.slice(0, 50);
        if (toUser.transactions.length   > 50) toUser.transactions   = toUser.transactions.slice(0, 50);

        // Firmar ambos registros
        fromUser.signature = signRecord(fromUser);
        toUser.signature   = signRecord(toUser);

        data.users[session.email]    = fromUser;
        data.users[toUser.email]     = toUser;

      } else if (type === "deposit") {
        fromUser.balance = parseFloat((fromUser.balance + amt).toFixed(2));
        fromUser.updatedAt = now;
        if (!fromUser.transactions) fromUser.transactions = [];
        fromUser.transactions.unshift({ id: txId, type: "deposit", amount: amt, description: description || "Depósito propio", date: now });
        if (fromUser.transactions.length > 50) fromUser.transactions = fromUser.transactions.slice(0, 50);
        fromUser.signature = signRecord(fromUser);
        data.users[session.email] = fromUser;

      } else if (type === "withdraw") {
        if (fromUser.balance < amt) return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: `Saldo insuficiente. Disponible: $${fromUser.balance.toFixed(2)}` }) };
        fromUser.balance = parseFloat((fromUser.balance - amt).toFixed(2));
        fromUser.updatedAt = now;
        if (!fromUser.transactions) fromUser.transactions = [];
        fromUser.transactions.unshift({ id: txId, type: "withdraw", amount: amt, description: description || "Retiro", date: now });
        if (fromUser.transactions.length > 50) fromUser.transactions = fromUser.transactions.slice(0, 50);
        fromUser.signature = signRecord(fromUser);
        data.users[session.email] = fromUser;
      }

      await saveData(data);

      return {
        statusCode: 200, headers,
        body: JSON.stringify({
          ok: true,
          txId,
          newBalance: fromUser.balance,
          type,
          amount: amt,
          message: type === "transfer" ? `Transferencia de $${amt.toFixed(2)} completada` :
                   type === "deposit"  ? `Depósito de $${amt.toFixed(2)} completado` :
                                         `Retiro de $${amt.toFixed(2)} completado`
        })
      };

    } catch(err) {
      console.error("TRANSFER error:", err.message);
      return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: "Error interno: " + err.message }) };
    }
  }

  return { statusCode: 405, headers, body: JSON.stringify({ ok: false, error: "Method not allowed" }) };
};
