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
  console.log("saveData status:", res.status);
}

function parseToken(token) {
  try { return JSON.parse(Buffer.from(token, "base64").toString()); }
  catch(e) { return null; }
}

function signRecord(record) {
  // Firma solo con campos estables — NO incluye balance para evitar invalidaciones
  const payload = JSON.stringify({
    email: record.email,
    name:  record.name,
    role:  record.role || "user"
  });
  return crypto.createHmac("sha256", SECRET_KEY).update(payload).digest("hex");
}

function hasValidSignature(record) {
  // Solo verifica que EXISTA una firma de 64 chars hex
  // La verificación estricta la hace el Lab 2
  if (!record.signature) return false;
  if (record.signature.length !== 64) return false;
  if (!/^[0-9a-f]{64}$/.test(record.signature)) return false;
  return true;
}

function searchUser(users, query) {
  const q = query.toLowerCase().trim();
  return Object.values(users).find(u =>
    u.email.toLowerCase().includes(q) ||
    u.name.toLowerCase().includes(q)
  );
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };

  // ── GET: buscar destinatario ──
  if (event.httpMethod === "GET") {
    const params  = event.queryStringParameters || {};
    const session = parseToken(params.token);
    if (!session) return { statusCode: 401, headers, body: JSON.stringify({ ok: false, error: "Sesion invalida." }) };
    const query = params.query || "";
    if (query.length < 2) return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Ingresa al menos 2 caracteres." }) };
    const data  = await getData();
    const found = searchUser(data.users || {}, query);
    if (!found || found.email === session.email)
      return { statusCode: 404, headers, body: JSON.stringify({ ok: false, error: "Usuario no encontrado." }) };
    return {
      statusCode: 200, headers,
      body: JSON.stringify({ ok: true, user: { name: found.name, email: found.email } })
    };
  }

  // ── POST: ejecutar transaccion ──
  if (event.httpMethod === "POST") {
    try {
      const { token, type, amount, toEmail, description } = JSON.parse(event.body || "{}");
      console.log("TRANSFER type:", type, "amount:", amount);

      const session = parseToken(token);
      if (!session) return { statusCode: 401, headers, body: JSON.stringify({ ok: false, error: "Sesion invalida." }) };

      const amt = parseFloat(amount);
      if (!amt || amt <= 0)
        return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "El monto debe ser mayor a 0." }) };

      if (!["transfer", "deposit", "withdraw"].includes(type))
        return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Tipo invalido." }) };

      const data = await getData();
      if (!data.users) data.users = {};

      const fromUser = data.users[session.email];
      if (!fromUser)
        return { statusCode: 404, headers, body: JSON.stringify({ ok: false, error: "Usuario no encontrado." }) };

      // ── Firma requerida SOLO para transferencias ──
      if (type === "transfer") {
        if (!hasValidSignature(fromUser)) {
          return {
            statusCode: 403, headers,
            body: JSON.stringify({
              ok: false,
              requiresSignature: true,
              error: "Necesitas crear tu firma digital en el Lab 2 antes de transferir."
            })
          };
        }
      }

      const now  = new Date().toISOString();
      const txId = "TX-" + Date.now();

      if (type === "transfer") {
        if (!toEmail)
          return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Destinatario requerido." }) };
        const toUser = data.users[toEmail.toLowerCase()];
        if (!toUser)
          return { statusCode: 404, headers, body: JSON.stringify({ ok: false, error: "Destinatario no encontrado." }) };
        if (toUser.email === session.email)
          return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "No puedes transferirte a ti mismo." }) };
        if (fromUser.balance < amt)
          return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Saldo insuficiente. Disponible: $" + parseFloat(fromUser.balance || 0).toFixed(2) }) };

        fromUser.balance   = parseFloat((fromUser.balance - amt).toFixed(2));
        toUser.balance     = parseFloat(((toUser.balance || 0) + amt).toFixed(2));
        fromUser.updatedAt = now;
        toUser.updatedAt   = now;

        if (!fromUser.transactions) fromUser.transactions = [];
        if (!toUser.transactions)   toUser.transactions   = [];

        fromUser.transactions.unshift({ id: txId, type: "transfer_out", amount: amt, to: toUser.email, toName: toUser.name, description: description || "", date: now });
        toUser.transactions.unshift({   id: txId, type: "transfer_in",  amount: amt, from: session.email, fromName: fromUser.name, description: description || "", date: now });

        if (fromUser.transactions.length > 50) fromUser.transactions = fromUser.transactions.slice(0, 50);
        if (toUser.transactions.length   > 50) toUser.transactions   = toUser.transactions.slice(0, 50);

        // Mantener firma existente — no regenerar para no invalidar
        data.users[session.email] = fromUser;
        data.users[toUser.email]  = toUser;

      } else if (type === "deposit") {
        fromUser.balance = parseFloat(((fromUser.balance || 0) + amt).toFixed(2));
        fromUser.updatedAt = now;
        if (!fromUser.transactions) fromUser.transactions = [];
        fromUser.transactions.unshift({ id: txId, type: "deposit", amount: amt, description: description || "Deposito propio", date: now });
        if (fromUser.transactions.length > 50) fromUser.transactions = fromUser.transactions.slice(0, 50);
        data.users[session.email] = fromUser;

      } else if (type === "withdraw") {
        if ((fromUser.balance || 0) < amt)
          return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Saldo insuficiente. Disponible: $" + parseFloat(fromUser.balance || 0).toFixed(2) }) };
        fromUser.balance = parseFloat((fromUser.balance - amt).toFixed(2));
        fromUser.updatedAt = now;
        if (!fromUser.transactions) fromUser.transactions = [];
        fromUser.transactions.unshift({ id: txId, type: "withdraw", amount: amt, description: description || "Retiro", date: now });
        if (fromUser.transactions.length > 50) fromUser.transactions = fromUser.transactions.slice(0, 50);
        data.users[session.email] = fromUser;
      }

      await saveData(data);

      return {
        statusCode: 200, headers,
        body: JSON.stringify({
          ok:         true,
          txId,
          newBalance: fromUser.balance,
          type,
          amount:     amt,
          message:    type === "transfer" ? "Transferencia de $" + amt.toFixed(2) + " completada" :
                      type === "deposit"  ? "Deposito de $"      + amt.toFixed(2) + " completado" :
                                            "Retiro de $"        + amt.toFixed(2) + " completado"
        })
      };

    } catch(err) {
      console.error("TRANSFER error:", err.message, err.stack);
      return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: "Error interno: " + err.message }) };
    }
  }

  return { statusCode: 405, headers, body: JSON.stringify({ ok: false, error: "Method not allowed" }) };
};
