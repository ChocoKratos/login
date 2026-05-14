// netlify/functions/posts.js
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

  // GET — obtener todos los posts
  if (event.httpMethod === "GET") {
    try {
      const data = await getData();
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true, posts: data.posts || [] }) };
    } catch(e) {
      return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: "Error al obtener posts." }) };
    }
  }

  // POST — crear post
  if (event.httpMethod === "POST") {
    try {
      const { token, title, content, image } = JSON.parse(event.body || "{}");

      const session = parseToken(token);
      if (!session) return { statusCode: 401, headers, body: JSON.stringify({ ok: false, error: "Sesión inválida." }) };

      if (!title || !content) return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Título y contenido son obligatorios." }) };

      const data = await getData();
      const post = {
        id:        Date.now().toString(),
        title:     title.trim(),
        content:   content.trim(),
        image:     image || null,
        author:    session.name,
        email:     session.email,
        createdAt: new Date().toISOString(),
        comments:  []
      };

      data.posts.unshift(post);
      await saveData(data);

      return { statusCode: 200, headers, body: JSON.stringify({ ok: true, post }) };
    } catch(e) {
      return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: "Error al crear post." }) };
    }
  }

  return { statusCode: 405, headers, body: JSON.stringify({ ok: false, error: "Method not allowed" }) };
};
