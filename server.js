const crypto = require("crypto");
const express = require("express");
const mongoose = require("mongoose");

const app = express();
app.set("trust proxy", 1);

app.use(
  express.json({
    limit: "2mb",
    verify: (req, res, buffer) => {
      req.rawBody = Buffer.from(buffer);
    },
  })
);

app.use(express.urlencoded({ extended: false, limit: "100kb" }));

/* -------------------------------------------------------------------------- */
/* Çevre değişkenleri                                                         */
/* -------------------------------------------------------------------------- */

const MONGO_URL = (process.env.MONGO_URL || "").trim();
const VERIFY_TOKEN = (process.env.VERIFY_TOKEN || "").trim();
const APP_SECRET = (process.env.APP_SECRET || "").trim();
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || "").trim();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const PORT = Number(process.env.PORT || 3000);

for (const [name, value] of Object.entries({
  MONGO_URL,
  VERIFY_TOKEN,
  APP_SECRET,
  ADMIN_USERNAME,
  ADMIN_PASSWORD,
})) {
  if (!value) {
    throw new Error(`${name} çevre değişkeni eksik.`);
  }
}

/* -------------------------------------------------------------------------- */
/* MongoDB şemaları                                                           */
/* -------------------------------------------------------------------------- */

const webhookEventSchema = new mongoose.Schema(
  {
    eventHash: { type: String, required: true, unique: true },
    object: { type: String, default: null },
    accountIds: { type: [String], default: [] },
    eventTypes: { type: [String], default: [] },
    payload: { type: mongoose.Schema.Types.Mixed, required: true },
    receivedAt: { type: Date, default: Date.now, index: true },
  },
  { versionKey: false, collection: "webhook_events" }
);

const commentSchema = new mongoose.Schema(
  {
    commentId: { type: String, required: true, unique: true },
    accountId: { type: String, required: true, index: true },
    authorId: { type: String, default: null, index: true },
    username: { type: String, default: null, index: true },
    mediaId: { type: String, default: null, index: true },
    mediaProductType: { type: String, default: null },
    parentCommentId: { type: String, default: null, index: true },
    isReply: { type: Boolean, default: false, index: true },
    text: { type: String, default: "" },
    eventTime: { type: Date, default: null, index: true },
    firstReceivedAt: { type: Date, default: Date.now },
    lastReceivedAt: { type: Date, default: Date.now },
    rawEventId: { type: mongoose.Schema.Types.ObjectId, default: null },
  },
  { versionKey: false, collection: "comments" }
);

const messageSchema = new mongoose.Schema(
  {
    mid: { type: String, required: true, unique: true },
    accountId: { type: String, required: true, index: true },
    senderId: { type: String, default: null, index: true },
    recipientId: { type: String, default: null, index: true },
    direction: {
      type: String,
      enum: ["incoming", "outgoing"],
      required: true,
      index: true,
    },
    text: { type: String, default: null },
    attachments: { type: Array, default: [] },
    replyTo: { type: mongoose.Schema.Types.Mixed, default: null },
    isSelf: { type: Boolean, default: false },
    isEcho: { type: Boolean, default: false },
    isDeleted: { type: Boolean, default: false },
    folder: { type: String, default: null },
    eventTime: { type: Date, default: null, index: true },
    firstReceivedAt: { type: Date, default: Date.now },
    lastReceivedAt: { type: Date, default: Date.now },
    rawEventId: { type: mongoose.Schema.Types.ObjectId, default: null },
  },
  { versionKey: false, collection: "messages" }
);

const WebhookEvent = mongoose.model("WebhookEvent", webhookEventSchema);
const Comment = mongoose.model("Comment", commentSchema);
const Message = mongoose.model("Message", messageSchema);

/* -------------------------------------------------------------------------- */
/* Genel yardımcılar                                                         */
/* -------------------------------------------------------------------------- */

function toDate(value) {
  if (value === null || value === undefined) return null;
  const number = Number(value);
  if (!Number.isFinite(number)) return null;
  return new Date(number < 1_000_000_000_000 ? number * 1000 : number);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function formatDate(value) {
  if (!value) return "Tarih yok";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Tarih yok";

  return new Intl.DateTimeFormat("tr-TR", {
    timeZone: "Europe/Istanbul",
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(date);
}

function clampInteger(value, min, max, fallback) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(parsed, min), max);
}

function safeEqual(left, right) {
  const leftHash = crypto.createHash("sha256").update(String(left)).digest();
  const rightHash = crypto.createHash("sha256").update(String(right)).digest();
  return crypto.timingSafeEqual(leftHash, rightHash);
}

function encodeQuery(params) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      query.set(key, String(value));
    }
  }
  const text = query.toString();
  return text ? `?${text}` : "";
}

/* -------------------------------------------------------------------------- */
/* Panel kimlik doğrulaması                                                   */
/* -------------------------------------------------------------------------- */

const failedAuth = new Map();
const AUTH_WINDOW_MS = 15 * 60 * 1000;
const AUTH_MAX_FAILURES = 10;

function panelAuth(req, res, next) {
  res.set({
    "Cache-Control": "no-store, max-age=0",
    Pragma: "no-cache",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
  });

  const ip = req.ip || "unknown";
  const now = Date.now();
  const state = failedAuth.get(ip);

  if (state && state.blockedUntil > now) {
    return res.status(429).send("Çok fazla hatalı giriş. Bir süre sonra tekrar dene.");
  }

  const authorization = req.get("authorization") || "";
  if (!authorization.startsWith("Basic ")) {
    res.set("WWW-Authenticate", 'Basic realm="b1rmod Panel", charset="UTF-8"');
    return res.status(401).send("Giriş gerekli.");
  }

  let decoded = "";
  try {
    decoded = Buffer.from(authorization.slice(6), "base64").toString("utf8");
  } catch {
    decoded = "";
  }

  const separatorIndex = decoded.indexOf(":");
  const username = separatorIndex >= 0 ? decoded.slice(0, separatorIndex) : "";
  const password = separatorIndex >= 0 ? decoded.slice(separatorIndex + 1) : "";

  const valid = safeEqual(username, ADMIN_USERNAME) && safeEqual(password, ADMIN_PASSWORD);

  if (!valid) {
    const previous = failedAuth.get(ip);
    const count = previous && previous.firstFailure > now - AUTH_WINDOW_MS
      ? previous.count + 1
      : 1;

    failedAuth.set(ip, {
      count,
      firstFailure: previous?.firstFailure || now,
      blockedUntil: count >= AUTH_MAX_FAILURES ? now + AUTH_WINDOW_MS : 0,
    });

    res.set("WWW-Authenticate", 'Basic realm="b1rmod Panel", charset="UTF-8"');
    return res.status(401).send("Kullanıcı adı veya şifre yanlış.");
  }

  failedAuth.delete(ip);
  return next();
}

/* -------------------------------------------------------------------------- */
/* Meta imza doğrulaması                                                      */
/* -------------------------------------------------------------------------- */

function verifyMetaSignature(req) {
  const receivedSignature = req.get("x-hub-signature-256");
  if (!receivedSignature || !receivedSignature.startsWith("sha256=")) return false;
  if (!req.rawBody || req.rawBody.length === 0) return false;

  const expectedSignature =
    "sha256=" +
    crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");

  const receivedBuffer = Buffer.from(receivedSignature, "utf8");
  const expectedBuffer = Buffer.from(expectedSignature, "utf8");

  if (receivedBuffer.length !== expectedBuffer.length) return false;
  return crypto.timingSafeEqual(receivedBuffer, expectedBuffer);
}

function detectEventTypes(body) {
  const types = new Set();

  for (const entry of body.entry || []) {
    for (const change of entry.changes || []) {
      if (change.field) types.add(change.field);
    }

    for (const messagingEvent of entry.messaging || []) {
      if (messagingEvent.message) types.add("messages");
      if (messagingEvent.read) types.add("messaging_seen");
      if (messagingEvent.reaction) types.add("message_reactions");
      if (messagingEvent.postback) types.add("messaging_postbacks");
    }
  }

  return Array.from(types);
}

async function normalizeWebhook(body, rawEventId) {
  const commentOperations = [];
  const messageOperations = [];

  for (const entry of body.entry || []) {
    const accountId = String(entry.id || "");

    for (const change of entry.changes || []) {
      if (change.field !== "comments") continue;

      const value = change.value || {};
      if (!value.id) continue;

      const commentId = String(value.id);
      const parentCommentId = value.parent_id ? String(value.parent_id) : null;
      const now = new Date();

      commentOperations.push({
        updateOne: {
          filter: { commentId },
          update: {
            $set: {
              accountId,
              authorId: value.from?.id ? String(value.from.id) : null,
              username: value.from?.username || null,
              mediaId: value.media?.id ? String(value.media.id) : null,
              mediaProductType: value.media?.media_product_type || null,
              parentCommentId,
              isReply: Boolean(parentCommentId),
              text: value.text || "",
              eventTime: toDate(entry.time),
              lastReceivedAt: now,
            },
            $setOnInsert: { firstReceivedAt: now, rawEventId },
          },
          upsert: true,
        },
      });
    }

    for (const messagingEvent of entry.messaging || []) {
      const message = messagingEvent.message;
      if (!message?.mid) continue;

      const senderId = messagingEvent.sender?.id
        ? String(messagingEvent.sender.id)
        : null;
      const recipientId = messagingEvent.recipient?.id
        ? String(messagingEvent.recipient.id)
        : null;
      const direction =
        message.is_self === true || senderId === accountId ? "outgoing" : "incoming";
      const now = new Date();

      messageOperations.push({
        updateOne: {
          filter: { mid: String(message.mid) },
          update: {
            $set: {
              accountId,
              senderId,
              recipientId,
              direction,
              text: message.text ?? null,
              attachments: message.attachments || [],
              replyTo: message.reply_to || null,
              isSelf: message.is_self === true,
              isEcho: message.is_echo === true,
              isDeleted: message.is_deleted === true,
              folder: messagingEvent.folder || null,
              eventTime: toDate(messagingEvent.timestamp || entry.time),
              lastReceivedAt: now,
            },
            $setOnInsert: { firstReceivedAt: now, rawEventId },
          },
          upsert: true,
        },
      });
    }
  }

  if (commentOperations.length > 0) {
    await Comment.bulkWrite(commentOperations, { ordered: false });
  }

  if (messageOperations.length > 0) {
    await Message.bulkWrite(messageOperations, { ordered: false });
  }

  return {
    comments: commentOperations.length,
    messages: messageOperations.length,
  };
}

/* -------------------------------------------------------------------------- */
/* Panel HTML                                                                 */
/* -------------------------------------------------------------------------- */

function layout({ title, active, stats, content }) {
  const commentsActive = active === "comments" ? "active" : "";
  const messagesActive = active === "messages" ? "active" : "";
  const statusActive = active === "status" ? "active" : "";

  return `<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>${escapeHtml(title)} · b1rmod Panel</title>
  <style>
    :root { color-scheme: dark; --bg:#0b0d12; --panel:#121620; --panel2:#171c28; --line:#293142; --text:#f4f6fb; --muted:#9da8ba; --accent:#8da2ff; --good:#52d89f; --warn:#ffc76b; }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--bg); color:var(--text); font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; }
    a { color:inherit; text-decoration:none; }
    .shell { width:min(1120px, calc(100% - 28px)); margin:0 auto; }
    header { position:sticky; top:0; z-index:10; border-bottom:1px solid var(--line); background:rgba(11,13,18,.93); backdrop-filter:blur(12px); }
    .top { min-height:68px; display:flex; align-items:center; justify-content:space-between; gap:18px; }
    .brand { font-weight:850; letter-spacing:-.03em; font-size:20px; }
    nav { display:flex; gap:8px; flex-wrap:wrap; }
    nav a { padding:9px 12px; border-radius:10px; color:var(--muted); }
    nav a.active, nav a:hover { color:var(--text); background:var(--panel2); }
    main { padding:28px 0 48px; }
    .stats { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-bottom:18px; }
    .stat { padding:17px; background:var(--panel); border:1px solid var(--line); border-radius:16px; }
    .stat strong { display:block; font-size:27px; letter-spacing:-.04em; }
    .stat span { color:var(--muted); font-size:13px; }
    .toolbar { display:flex; gap:10px; align-items:center; flex-wrap:wrap; padding:14px; margin-bottom:14px; background:var(--panel); border:1px solid var(--line); border-radius:16px; }
    input, select, button { font:inherit; }
    input, select { min-height:42px; border:1px solid var(--line); border-radius:10px; background:#0e121a; color:var(--text); padding:0 12px; }
    input[type=search] { flex:1 1 280px; }
    button, .button { min-height:42px; display:inline-flex; align-items:center; justify-content:center; border:0; border-radius:10px; padding:0 15px; background:var(--accent); color:#080b12; font-weight:800; cursor:pointer; }
    .list { display:grid; gap:10px; }
    .card { background:var(--panel); border:1px solid var(--line); border-radius:16px; padding:17px; overflow-wrap:anywhere; }
    .card-head { display:flex; justify-content:space-between; align-items:flex-start; gap:14px; margin-bottom:10px; }
    .identity { font-weight:800; }
    .time { color:var(--muted); font-size:13px; text-align:right; white-space:nowrap; }
    .text { white-space:pre-wrap; line-height:1.55; font-size:15px; }
    .meta { display:flex; gap:7px; flex-wrap:wrap; margin-top:13px; }
    .pill { padding:5px 8px; border-radius:999px; background:var(--panel2); color:var(--muted); font-size:12px; border:1px solid var(--line); }
    .pill.good { color:var(--good); }
    .pill.warn { color:var(--warn); }
    details { margin-top:12px; color:var(--muted); font-size:12px; }
    summary { cursor:pointer; }
    .empty { text-align:center; padding:48px 20px; color:var(--muted); background:var(--panel); border:1px solid var(--line); border-radius:16px; }
    .pagination { display:flex; justify-content:space-between; align-items:center; gap:12px; margin-top:18px; }
    .pagination .button { background:var(--panel2); color:var(--text); border:1px solid var(--line); }
    .pagination .disabled { opacity:.35; pointer-events:none; }
    .page-info { color:var(--muted); font-size:13px; }
    .status-grid { display:grid; gap:12px; grid-template-columns:repeat(2,1fr); }
    .code { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; background:#0d1119; border:1px solid var(--line); border-radius:10px; padding:12px; overflow:auto; }
    @media (max-width:720px) {
      .top { align-items:flex-start; flex-direction:column; padding:14px 0; }
      .stats, .status-grid { grid-template-columns:1fr; }
      .card-head { flex-direction:column; }
      .time { text-align:left; white-space:normal; }
    }
  </style>
</head>
<body>
<header>
  <div class="shell top">
    <a class="brand" href="/panel/comments">b1rmod Panel</a>
    <nav>
      <a class="${commentsActive}" href="/panel/comments">Yorumlar</a>
      <a class="${messagesActive}" href="/panel/messages">DM’ler</a>
      <a class="${statusActive}" href="/panel/status">Sistem</a>
    </nav>
  </div>
</header>
<main class="shell">
  <section class="stats">
    <div class="stat"><strong>${stats.comments}</strong><span>Toplam yorum</span></div>
    <div class="stat"><strong>${stats.messages}</strong><span>Toplam DM</span></div>
    <div class="stat"><strong>${stats.rawEvents}</strong><span>Ham webhook</span></div>
  </section>
  ${content}
</main>
</body>
</html>`;
}

async function getStats() {
  const [comments, messages, rawEvents] = await Promise.all([
    Comment.countDocuments({}),
    Message.countDocuments({}),
    WebhookEvent.countDocuments({}),
  ]);
  return { comments, messages, rawEvents };
}

function paginationHtml({ page, pages, basePath, params }) {
  const previous = page > 1
    ? `${basePath}${encodeQuery({ ...params, page: page - 1 })}`
    : "#";
  const next = page < pages
    ? `${basePath}${encodeQuery({ ...params, page: page + 1 })}`
    : "#";

  return `<div class="pagination">
    <a class="button ${page <= 1 ? "disabled" : ""}" href="${escapeHtml(previous)}">← Önceki</a>
    <div class="page-info">Sayfa ${page} / ${pages}</div>
    <a class="button ${page >= pages ? "disabled" : ""}" href="${escapeHtml(next)}">Sonraki →</a>
  </div>`;
}

/* -------------------------------------------------------------------------- */
/* Panel rotaları                                                             */
/* -------------------------------------------------------------------------- */

app.get("/", (req, res) => {
  if ((req.hostname || "").toLowerCase().startsWith("panel.")) {
    return res.redirect(302, "/panel/comments");
  }

  return res.status(200).json({
    status: "ok",
    service: "instagram-logger",
    panel: "https://panel.b1rmod.com/panel/comments",
  });
});

app.use("/panel", panelAuth);

app.get("/panel", (req, res) => res.redirect(302, "/panel/comments"));

app.get("/panel/comments", async (req, res, next) => {
  try {
    const page = clampInteger(req.query.page, 1, 100000, 1);
    const limit = clampInteger(req.query.limit, 10, 100, 50);
    const q = String(req.query.q || "").trim().slice(0, 200);
    const type = ["all", "main", "reply"].includes(req.query.type)
      ? req.query.type
      : "all";

    const filter = {};
    if (type === "main") filter.isReply = false;
    if (type === "reply") filter.isReply = true;

    if (q) {
      const regex = new RegExp(escapeRegex(q), "i");
      filter.$or = [{ text: regex }, { username: regex }, { commentId: regex }];
    }

    const [items, total, stats] = await Promise.all([
      Comment.find(filter)
        .sort({ eventTime: -1, firstReceivedAt: -1, _id: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      Comment.countDocuments(filter),
      getStats(),
    ]);

    const pages = Math.max(1, Math.ceil(total / limit));
    const safePage = Math.min(page, pages);

    const cards = items.length
      ? items
          .map(
            (item) => `<article class="card">
              <div class="card-head">
                <div class="identity">@${escapeHtml(item.username || "kullanıcı-adı-yok")}</div>
                <div class="time">${escapeHtml(formatDate(item.eventTime || item.firstReceivedAt))}</div>
              </div>
              <div class="text">${escapeHtml(item.text || "(Boş yorum)")}</div>
              <div class="meta">
                <span class="pill ${item.isReply ? "warn" : "good"}">${item.isReply ? "Yanıt" : "Ana yorum"}</span>
                <span class="pill">${escapeHtml(item.mediaProductType || "Medya türü yok")}</span>
                <span class="pill">Medya: ${escapeHtml(item.mediaId || "—")}</span>
              </div>
              <details>
                <summary>Teknik bilgiler</summary>
                <div>Yorum ID: ${escapeHtml(item.commentId)}</div>
                <div>Yazar ID: ${escapeHtml(item.authorId || "—")}</div>
                <div>Ana yorum ID: ${escapeHtml(item.parentCommentId || "—")}</div>
              </details>
            </article>`
          )
          .join("")
      : '<div class="empty">Bu filtreyle eşleşen yorum bulunamadı.</div>';

    const content = `
      <form class="toolbar" method="get" action="/panel/comments">
        <input type="search" name="q" value="${escapeHtml(q)}" placeholder="Yorum, kullanıcı adı veya ID ara">
        <select name="type">
          <option value="all" ${type === "all" ? "selected" : ""}>Tümü</option>
          <option value="main" ${type === "main" ? "selected" : ""}>Ana yorumlar</option>
          <option value="reply" ${type === "reply" ? "selected" : ""}>Yanıtlar</option>
        </select>
        <select name="limit">
          ${[25, 50, 100]
            .map((value) => `<option value="${value}" ${limit === value ? "selected" : ""}>${value} / sayfa</option>`)
            .join("")}
        </select>
        <button type="submit">Filtrele</button>
      </form>
      <div class="list">${cards}</div>
      ${paginationHtml({
        page: safePage,
        pages,
        basePath: "/panel/comments",
        params: { q, type, limit },
      })}`;

    return res.status(200).send(
      layout({ title: "Yorumlar", active: "comments", stats, content })
    );
  } catch (error) {
    return next(error);
  }
});

app.get("/panel/messages", async (req, res, next) => {
  try {
    const page = clampInteger(req.query.page, 1, 100000, 1);
    const limit = clampInteger(req.query.limit, 10, 100, 50);
    const q = String(req.query.q || "").trim().slice(0, 200);
    const direction = ["all", "incoming", "outgoing"].includes(req.query.direction)
      ? req.query.direction
      : "all";

    const filter = {};
    if (direction !== "all") filter.direction = direction;

    if (q) {
      const regex = new RegExp(escapeRegex(q), "i");
      filter.$or = [
        { text: regex },
        { senderId: regex },
        { recipientId: regex },
        { mid: regex },
      ];
    }

    const [items, total, stats] = await Promise.all([
      Message.find(filter)
        .sort({ eventTime: -1, firstReceivedAt: -1, _id: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      Message.countDocuments(filter),
      getStats(),
    ]);

    const pages = Math.max(1, Math.ceil(total / limit));
    const safePage = Math.min(page, pages);

    const cards = items.length
      ? items
          .map((item) => {
            const attachmentCount = Array.isArray(item.attachments)
              ? item.attachments.length
              : 0;
            const deleted = item.isDeleted ? "(Silinmiş mesaj)" : null;
            const body = item.text || deleted || (attachmentCount ? `[${attachmentCount} ek]` : "(Metinsiz mesaj)");

            return `<article class="card">
              <div class="card-head">
                <div class="identity">${item.direction === "incoming" ? "Gelen DM" : "Gönderilen DM"}</div>
                <div class="time">${escapeHtml(formatDate(item.eventTime || item.firstReceivedAt))}</div>
              </div>
              <div class="text">${escapeHtml(body)}</div>
              <div class="meta">
                <span class="pill ${item.direction === "incoming" ? "good" : "warn"}">${item.direction === "incoming" ? "Gelen" : "Giden"}</span>
                ${attachmentCount ? `<span class="pill">${attachmentCount} ek</span>` : ""}
                ${item.isDeleted ? '<span class="pill warn">Silinmiş</span>' : ""}
                ${item.replyTo ? '<span class="pill">Yanıt</span>' : ""}
              </div>
              <details>
                <summary>Teknik bilgiler</summary>
                <div>Mesaj ID: ${escapeHtml(item.mid)}</div>
                <div>Gönderen ID: ${escapeHtml(item.senderId || "—")}</div>
                <div>Alıcı ID: ${escapeHtml(item.recipientId || "—")}</div>
              </details>
            </article>`;
          })
          .join("")
      : '<div class="empty">Bu filtreyle eşleşen DM bulunamadı.</div>';

    const content = `
      <form class="toolbar" method="get" action="/panel/messages">
        <input type="search" name="q" value="${escapeHtml(q)}" placeholder="Mesaj metni veya ID ara">
        <select name="direction">
          <option value="all" ${direction === "all" ? "selected" : ""}>Tümü</option>
          <option value="incoming" ${direction === "incoming" ? "selected" : ""}>Gelenler</option>
          <option value="outgoing" ${direction === "outgoing" ? "selected" : ""}>Gönderilenler</option>
        </select>
        <select name="limit">
          ${[25, 50, 100]
            .map((value) => `<option value="${value}" ${limit === value ? "selected" : ""}>${value} / sayfa</option>`)
            .join("")}
        </select>
        <button type="submit">Filtrele</button>
      </form>
      <div class="list">${cards}</div>
      ${paginationHtml({
        page: safePage,
        pages,
        basePath: "/panel/messages",
        params: { q, direction, limit },
      })}`;

    return res.status(200).send(
      layout({ title: "DM’ler", active: "messages", stats, content })
    );
  } catch (error) {
    return next(error);
  }
});

app.get("/panel/status", async (req, res, next) => {
  try {
    const [stats, lastWebhook, lastComment, lastMessage] = await Promise.all([
      getStats(),
      WebhookEvent.findOne({}).sort({ receivedAt: -1 }).lean(),
      Comment.findOne({}).sort({ eventTime: -1, firstReceivedAt: -1 }).lean(),
      Message.findOne({}).sort({ eventTime: -1, firstReceivedAt: -1 }).lean(),
    ]);

    const content = `<div class="status-grid">
      <section class="card">
        <div class="identity">Bağlantı durumu</div>
        <div class="meta">
          <span class="pill good">Node.js çalışıyor</span>
          <span class="pill ${mongoose.connection.readyState === 1 ? "good" : "warn"}">MongoDB ${mongoose.connection.readyState === 1 ? "bağlı" : "bağlı değil"}</span>
          <span class="pill good">İmza doğrulaması aktif</span>
        </div>
      </section>
      <section class="card">
        <div class="identity">Son hareketler</div>
        <div class="code">Son webhook: ${escapeHtml(formatDate(lastWebhook?.receivedAt))}<br>Son yorum: ${escapeHtml(formatDate(lastComment?.eventTime || lastComment?.firstReceivedAt))}<br>Son DM: ${escapeHtml(formatDate(lastMessage?.eventTime || lastMessage?.firstReceivedAt))}</div>
      </section>
    </div>`;

    return res.status(200).send(
      layout({ title: "Sistem", active: "status", stats, content })
    );
  } catch (error) {
    return next(error);
  }
});

/* -------------------------------------------------------------------------- */
/* Webhook                                                                    */
/* -------------------------------------------------------------------------- */

app.get("/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token === VERIFY_TOKEN) {
    console.log("Webhook Meta tarafından doğrulandı.");
    return res.status(200).send(challenge);
  }

  if (mode || token) {
    return res.status(403).send("Webhook doğrulaması başarısız.");
  }

  return res.status(200).send("Instagram webhook çalışıyor.");
});

app.post("/webhook", async (req, res) => {
  if (!verifyMetaSignature(req)) {
    console.error("Geçersiz Meta webhook imzası reddedildi.");
    return res.status(401).send("INVALID_SIGNATURE");
  }

  try {
    const body = req.body;

    if (!body || body.object !== "instagram" || !Array.isArray(body.entry)) {
      return res.status(400).send("INVALID_PAYLOAD");
    }

    const eventTypes = detectEventTypes(body);
    const eventHash = crypto.createHash("sha256").update(req.rawBody).digest("hex");
    const accountIds = body.entry
      .map((entry) => String(entry.id || ""))
      .filter(Boolean);

    let rawEvent;

    try {
      rawEvent = await WebhookEvent.findOneAndUpdate(
        { eventHash },
        {
          $setOnInsert: {
            eventHash,
            object: body.object || null,
            accountIds,
            eventTypes,
            payload: body,
            receivedAt: new Date(),
          },
        },
        { upsert: true, new: true, setDefaultsOnInsert: true }
      );
    } catch (error) {
      if (error?.code === 11000) {
        rawEvent = await WebhookEvent.findOne({ eventHash });
      } else {
        throw error;
      }
    }

    if (!rawEvent) throw new Error("Ham webhook kaydı oluşturulamadı.");

    const result = await normalizeWebhook(body, rawEvent._id);

    console.log(
      [
        "Webhook kaydedildi",
        `tür=${eventTypes.join(",") || "bilinmiyor"}`,
        `yorum=${result.comments}`,
        `dm=${result.messages}`,
      ].join(" | ")
    );

    return res.status(200).send("EVENT_RECEIVED");
  } catch (error) {
    console.error("Webhook işleme hatası:", {
      name: error?.name || "Error",
      message: error?.message || "Bilinmeyen hata",
      code: error?.code || null,
    });
    return res.status(500).send("WEBHOOK_ERROR");
  }
});

app.get("/health", (req, res) => {
  return res.status(200).json({
    status: "ok",
    mongodb: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    signatureVerification: "enabled",
    time: new Date().toISOString(),
  });
});

/* -------------------------------------------------------------------------- */
/* Hata yakalama                                                              */
/* -------------------------------------------------------------------------- */

app.use((error, req, res, next) => {
  console.error("Uygulama hatası:", {
    name: error?.name || "Error",
    message: error?.message || "Bilinmeyen hata",
  });

  if (req.path.startsWith("/panel")) {
    return res.status(500).send("Panel yüklenirken bir hata oluştu.");
  }

  return res.status(500).json({ error: "INTERNAL_SERVER_ERROR" });
});

/* -------------------------------------------------------------------------- */
/* Başlatma                                                                   */
/* -------------------------------------------------------------------------- */

mongoose
  .connect(MONGO_URL)
  .then(() => {
    console.log("MongoDB bağlantısı başarılı.");
    app.listen(PORT, () => {
      console.log(`Sunucu ${PORT} portunda çalışıyor.`);
    });
  })
  .catch((error) => {
    console.error("MongoDB bağlantı hatası:", error);
    process.exit(1);
  });
