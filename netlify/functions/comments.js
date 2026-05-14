// netlify/functions/comments.js
const fetch = require("node-fetch");

const JSONBIN_KEY = process.env.JSONBIN_KEY;
const JSONBIN_BIN = process.env.JSONBIN_BIN;
const BASE_URL    = `https://api.jsonbin.io/v3/b/${JSONBIN_BIN}`;

const headers = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json"
};

async function getData() {
  const res  = await fetch(BASE_URL + "/latest", {
    headers: { "X-Master-Key": JSONBIN_KEY }
  });
  const json = await res.json();
  return json.record || { posts: [] };
}

async function saveData(data) {
  await fetch(BASE_URL, {
    method:  "PUT",
    headers: { "X-Master-Key": JSONBIN_KEY, "Content-Type": "application/json" },
    body:    JSON.stringify(data)
  });
}

function parseToken(token) {
  try { return JSON.parse(Buffer.from(token, "base64").toString()); }
  catch(e) { return null; }
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };
  if (event.httpMethod !== "POST")    return { statusCode: 405, headers, body: JSON.stringify({ ok: false, error: "Method not allowed" }) };

  try {
    const { token, postId, comment } = JSON.parse(event.body || "{}");

    const session = parseToken(token);
    if (!session) return { statusCode: 401, headers, body: JSON.stringify({ ok: false, error: "Debes iniciar sesión para comentar." }) };
    if (!postId || !comment) return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Datos incompletos." }) };

    const data = await getData();
    const post = data.posts.find(p => p.id === postId);
    if (!post) return { statusCode: 404, headers, body: JSON.stringify({ ok: false, error: "Post no encontrado." }) };

    const newComment = {
      id:        Date.now().toString(),
      author:    session.name,
      email:     session.email,
      text:      comment.trim(),
      createdAt: new Date().toISOString()
    };

    post.comments.push(newComment);
    await saveData(data);

    return { statusCode: 200, headers, body: JSON.stringify({ ok: true, comment: newComment }) };
  } catch(e) {
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: "Error al guardar comentario." }) };
  }
};
