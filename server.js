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
const RAW_EVENT_RETENTION_DAYS = 7;
const RAW_EVENT_TTL_MS = RAW_EVENT_RETENTION_DAYS * 24 * 60 * 60 * 1000;
const PANEL_CSRF_TOKEN = crypto.randomBytes(32).toString("hex");

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
    processedAt: { type: Date, default: null, index: true },
    expiresAt: { type: Date, required: true },
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
    status: {
      type: String,
      enum: ["inbox", "archived"],
      default: "inbox",
      index: true,
    },
    statusUpdatedAt: { type: Date, default: Date.now },
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
    status: {
      type: String,
      enum: ["inbox", "archived"],
      default: "inbox",
      index: true,
    },
    statusUpdatedAt: { type: Date, default: Date.now },
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

function safeReturnTo(value, fallback = "/panel/comments") {
  const candidate = String(value || "");
  const allowed = [
    "/panel/comments",
    "/panel/comments/archive",
    "/panel/messages",
    "/panel/messages/archive",
    "/panel/status",
  ];

  const isAllowed = allowed.some(
    (route) => candidate === route || candidate.startsWith(`${route}?`)
  );

  if (!isAllowed || candidate.startsWith("//") || candidate.includes("\\")) {
    return fallback;
  }

  return candidate.slice(0, 1000);
}

function verifyPanelCsrf(req) {
  return safeEqual(req.body?.csrf || "", PANEL_CSRF_TOKEN);
}

function selectedValues(value, max = 100) {
  const values = Array.isArray(value) ? value : value ? [value] : [];
  return Array.from(new Set(values.map((item) => String(item).trim()).filter(Boolean))).slice(
    0,
    max
  );
}

function redirectWithNotice(res, returnTo, notice) {
  const target = safeReturnTo(returnTo);
  const separator = target.includes("?") ? "&" : "?";
  return res.redirect(303, `${target}${separator}notice=${encodeURIComponent(notice)}`);
}

async function updateRawEventAfterRemoval(rawEvent, payload) {
  payload.entry = (payload.entry || []).filter((entry) => {
    const hasChanges = Array.isArray(entry.changes) && entry.changes.length > 0;
    const hasMessaging = Array.isArray(entry.messaging) && entry.messaging.length > 0;
    return hasChanges || hasMessaging;
  });

  if (payload.entry.length === 0) {
    await WebhookEvent.deleteOne({ _id: rawEvent._id });
    return;
  }

  rawEvent.payload = payload;
  rawEvent.eventTypes = detectEventTypes(payload);
  rawEvent.markModified("payload");
  await rawEvent.save();
}

async function removeCommentFromRawEvent(rawEventId, commentId) {
  if (!rawEventId) return;

  const rawEvent = await WebhookEvent.findById(rawEventId);
  if (!rawEvent) return;

  const payload = rawEvent.payload || {};
  let removed = false;

  for (const entry of payload.entry || []) {
    if (!Array.isArray(entry.changes)) continue;

    entry.changes = entry.changes.filter((change) => {
      const isTarget =
        change?.field === "comments" &&
        String(change?.value?.id || "") === String(commentId);

      if (isTarget) removed = true;
      return !isTarget;
    });
  }

  if (removed) await updateRawEventAfterRemoval(rawEvent, payload);
}

async function removeMessageFromRawEvent(rawEventId, mid) {
  if (!rawEventId) return;

  const rawEvent = await WebhookEvent.findById(rawEventId);
  if (!rawEvent) return;

  const payload = rawEvent.payload || {};
  let removed = false;

  for (const entry of payload.entry || []) {
    if (!Array.isArray(entry.messaging)) continue;

    entry.messaging = entry.messaging.filter((event) => {
      const isTarget = String(event?.message?.mid || "") === String(mid);
      if (isTarget) removed = true;
      return !isTarget;
    });
  }

  if (removed) await updateRawEventAfterRemoval(rawEvent, payload);
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
            $setOnInsert: {
              firstReceivedAt: now,
              rawEventId,
              status: "inbox",
              statusUpdatedAt: now,
            },
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
            $setOnInsert: {
              firstReceivedAt: now,
              rawEventId,
              status: "inbox",
              statusUpdatedAt: now,
            },
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

function navLink({ href, label, count, active }) {
  return `<a class="${active ? "active" : ""}" href="${href}">
    ${escapeHtml(label)} <span class="nav-badge">${count}</span>
  </a>`;
}

function layout({ title, active, stats, content }) {
  return `<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>${escapeHtml(title)} · b1rmod Panel</title>
  <style>
    :root { color-scheme:dark; --bg:#0b0d12; --panel:#121620; --panel2:#171c28; --line:#293142; --text:#f4f6fb; --muted:#9da8ba; --accent:#8da2ff; --good:#52d89f; --warn:#ffc76b; --danger:#ff7b86; --archive:#b59cff; }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--bg); color:var(--text); font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; }
    a { color:inherit; text-decoration:none; }
    .shell { width:min(1160px, calc(100% - 28px)); margin:0 auto; }
    header { position:sticky; top:0; z-index:10; border-bottom:1px solid var(--line); background:rgba(11,13,18,.94); backdrop-filter:blur(12px); }
    .top { min-height:72px; display:flex; align-items:center; justify-content:space-between; gap:18px; }
    .brand { font-weight:900; letter-spacing:-.035em; font-size:20px; }
    nav { display:flex; gap:7px; flex-wrap:wrap; justify-content:flex-end; }
    nav a { display:flex; align-items:center; gap:7px; padding:9px 11px; border-radius:10px; color:var(--muted); }
    nav a.active, nav a:hover { color:var(--text); background:var(--panel2); }
    .nav-badge { min-width:22px; height:22px; display:inline-flex; align-items:center; justify-content:center; padding:0 6px; border-radius:999px; background:#0d1119; border:1px solid var(--line); color:var(--text); font-size:11px; }
    main { padding:28px 0 48px; }
    .stats { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:18px; }
    .stat { padding:17px; background:var(--panel); border:1px solid var(--line); border-radius:16px; }
    .stat strong { display:block; font-size:27px; letter-spacing:-.04em; }
    .stat span { color:var(--muted); font-size:13px; }
    .page-title { display:flex; align-items:end; justify-content:space-between; gap:14px; margin:0 0 14px; }
    .page-title h1 { margin:0; font-size:24px; letter-spacing:-.035em; }
    .page-title p { margin:5px 0 0; color:var(--muted); font-size:13px; }
    .toolbar, .bulkbar { display:flex; gap:10px; align-items:center; flex-wrap:wrap; padding:14px; margin-bottom:14px; background:var(--panel); border:1px solid var(--line); border-radius:16px; }
    .bulkbar { position:sticky; top:84px; z-index:8; background:rgba(18,22,32,.96); }
    input, select, button { font:inherit; }
    input, select { min-height:42px; border:1px solid var(--line); border-radius:10px; background:#0e121a; color:var(--text); padding:0 12px; }
    input[type=search] { flex:1 1 280px; }
    input[type=checkbox] { width:18px; height:18px; min-height:0; accent-color:var(--accent); }
    button, .button { min-height:42px; display:inline-flex; align-items:center; justify-content:center; border:0; border-radius:10px; padding:0 15px; background:var(--accent); color:#080b12; font-weight:850; cursor:pointer; }
    button:hover, .button:hover { filter:brightness(1.06); }
    .button-secondary { background:var(--panel2); color:var(--text); border:1px solid var(--line); }
    .button-archive { background:#332b4f; color:#e4ddff; border:1px solid #544776; }
    .button-danger { background:#3b2026; color:#ffd8dc; border:1px solid #6b3039; }
    .select-all { display:flex; align-items:center; gap:8px; color:var(--muted); font-size:13px; margin-right:auto; }
    .list { display:grid; gap:10px; }
    .card { position:relative; background:var(--panel); border:1px solid var(--line); border-radius:16px; padding:17px; overflow-wrap:anywhere; transition:.16s ease; }
    .card.inbox { border-color:#45569a; box-shadow:inset 4px 0 0 var(--accent); }
    .card.archived { border-color:#4b426e; background:#11131c; }
    .card:hover { transform:translateY(-1px); }
    .card-select { position:absolute; top:17px; left:17px; }
    .card-body { padding-left:31px; }
    .card-head { display:flex; justify-content:space-between; align-items:flex-start; gap:14px; margin-bottom:10px; }
    .identity { font-weight:850; }
    .time { color:var(--muted); font-size:13px; text-align:right; white-space:nowrap; }
    .text { white-space:pre-wrap; line-height:1.55; font-size:15px; }
    .meta { display:flex; gap:7px; flex-wrap:wrap; margin-top:13px; }
    .pill { padding:5px 8px; border-radius:999px; background:var(--panel2); color:var(--muted); font-size:12px; border:1px solid var(--line); }
    .pill.good { color:var(--good); }
    .pill.warn { color:var(--warn); }
    .pill.archive { color:var(--archive); }
    .parent-preview { margin-top:13px; padding:12px; border-radius:12px; background:#0e121a; border:1px solid var(--line); color:var(--muted); }
    .parent-preview strong { color:var(--text); display:block; margin-bottom:5px; }
    .actions { display:flex; gap:8px; flex-wrap:wrap; margin-top:14px; }
    .actions form { margin:0; }
    .actions button { min-height:36px; padding:0 12px; font-size:13px; }
    .notice { margin-bottom:14px; padding:12px 14px; border:1px solid #425487; border-radius:12px; background:#121a31; color:#dce4ff; }
    details { margin-top:12px; color:var(--muted); font-size:12px; }
    summary { cursor:pointer; }
    .empty { text-align:center; padding:48px 20px; color:var(--muted); background:var(--panel); border:1px solid var(--line); border-radius:16px; }
    .pagination { display:flex; justify-content:space-between; align-items:center; gap:12px; margin-top:18px; }
    .pagination .button { background:var(--panel2); color:var(--text); border:1px solid var(--line); }
    .pagination .disabled { opacity:.35; pointer-events:none; }
    .page-info { color:var(--muted); font-size:13px; }
    .status-grid { display:grid; gap:12px; grid-template-columns:repeat(2,1fr); }
    .code { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; background:#0d1119; border:1px solid var(--line); border-radius:10px; padding:12px; overflow:auto; }
    @media (max-width:980px) { .stats { grid-template-columns:repeat(2,1fr); } .top { align-items:flex-start; flex-direction:column; padding:14px 0; } nav { justify-content:flex-start; } }
    @media (max-width:720px) { .stats,.status-grid { grid-template-columns:1fr; } .card-head,.page-title { flex-direction:column; align-items:flex-start; } .time { text-align:left; white-space:normal; } .actions { display:grid; grid-template-columns:1fr 1fr; } .actions button { width:100%; } .bulkbar { top:132px; } }
  </style>
</head>
<body>
<header>
  <div class="shell top">
    <a class="brand" href="/panel/comments">b1rmod Panel</a>
    <nav>
      ${navLink({ href: "/panel/comments", label: "Yorumlar", count: stats.commentInbox, active: active === "comments" })}
      ${navLink({ href: "/panel/comments/archive", label: "Arşivlenen yorumlar", count: stats.commentArchive, active: active === "commentArchive" })}
      ${navLink({ href: "/panel/messages", label: "DM’ler", count: stats.messageInbox, active: active === "messages" })}
      ${navLink({ href: "/panel/messages/archive", label: "Arşivlenen DM’ler", count: stats.messageArchive, active: active === "messageArchive" })}
      <a class="${active === "status" ? "active" : ""}" href="/panel/status">Sistem</a>
    </nav>
  </div>
</header>
<main class="shell">
  <section class="stats">
    <div class="stat"><strong>${stats.commentInbox}</strong><span>Gelen kutusundaki yorum</span></div>
    <div class="stat"><strong>${stats.commentArchive}</strong><span>Arşivlenen yorum</span></div>
    <div class="stat"><strong>${stats.messageInbox}</strong><span>Gelen kutusundaki DM</span></div>
    <div class="stat"><strong>${stats.messageArchive}</strong><span>Arşivlenen DM</span></div>
  </section>
  ${content}
</main>
<script>
  function toggleAll(source, className) {
    document.querySelectorAll('.' + className).forEach(function (box) {
      box.checked = source.checked;
    });
  }

  function confirmBulk(form) {
    const selected = document.querySelectorAll('input[name="ids"]:checked').length;
    if (!selected) {
      alert('Önce en az bir kayıt seç.');
      return false;
    }

    const action = form.querySelector('select[name="action"]').value;
    if (action === 'delete') {
      return confirm(selected + ' kayıt veritabanından kalıcı olarak silinecek. Bu işlem geri alınamaz.');
    }

    return true;
  }
</script>
</body>
</html>`;
}

async function getStats() {
  const [commentInbox, commentArchive, messageInbox, messageArchive, rawEvents] =
    await Promise.all([
      Comment.countDocuments({ status: "inbox" }),
      Comment.countDocuments({ status: "archived" }),
      Message.countDocuments({ status: "inbox" }),
      Message.countDocuments({ status: "archived" }),
      WebhookEvent.countDocuments({}),
    ]);

  return {
    commentInbox,
    commentArchive,
    messageInbox,
    messageArchive,
    comments: commentInbox + commentArchive,
    messages: messageInbox + messageArchive,
    rawEvents,
  };
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

function noticeHtml(code) {
  const messages = {
    archived: "Kayıt arşive taşındı.",
    restored: "Kayıt gelen kutusuna geri taşındı.",
    deleted: "Kayıt ve bağlı ham webhook verisi kalıcı olarak silindi.",
    "bulk-archived": "Seçilen kayıtlar arşive taşındı.",
    "bulk-restored": "Seçilen kayıtlar gelen kutusuna geri taşındı.",
    "bulk-deleted": "Seçilen kayıtlar kalıcı olarak silindi.",
    "nothing-selected": "Herhangi bir kayıt seçilmedi.",
  };

  return messages[code]
    ? `<div class="notice">${escapeHtml(messages[code])}</div>`
    : "";
}

function bulkBar({ formId, endpoint, returnTo, archived, checkboxClass }) {
  return `<form id="${formId}" class="bulkbar" method="post" action="${endpoint}" onsubmit="return confirmBulk(this);">
    <input type="hidden" name="csrf" value="${PANEL_CSRF_TOKEN}">
    <input type="hidden" name="returnTo" value="${escapeHtml(returnTo)}">
    <label class="select-all">
      <input type="checkbox" onchange="toggleAll(this, '${checkboxClass}')"> Bu sayfadakilerin tümünü seç
    </label>
    <select name="action">
      ${archived ? '<option value="restore">Gelen kutusuna taşı</option>' : '<option value="archive">Arşivle</option>'}
      <option value="delete">Kalıcı sil</option>
    </select>
    <button type="submit">Seçililere uygula</button>
  </form>`;
}

function commentCard({ item, archived, parent, returnTo, formId, checkboxClass }) {
  const parentPreview = item.isReply
    ? `<div class="parent-preview"><strong>Şu yoruma yanıt:</strong>${
        parent
          ? `<div>@${escapeHtml(parent.username || "kullanıcı-adı-yok")}: ${escapeHtml(parent.text || "(Boş yorum)")}</div>`
          : "<div>Ana yorum henüz veritabanında bulunmuyor.</div>"
      }</div>`
    : "";

  const stateAction = archived
    ? `<form method="post" action="/panel/comments/${encodeURIComponent(item.commentId)}/restore">
        <input type="hidden" name="csrf" value="${PANEL_CSRF_TOKEN}">
        <input type="hidden" name="returnTo" value="${escapeHtml(returnTo)}">
        <button class="button-secondary" type="submit">↩ Gelen kutusuna taşı</button>
      </form>`
    : `<form method="post" action="/panel/comments/${encodeURIComponent(item.commentId)}/archive">
        <input type="hidden" name="csrf" value="${PANEL_CSRF_TOKEN}">
        <input type="hidden" name="returnTo" value="${escapeHtml(returnTo)}">
        <button class="button-archive" type="submit">Arşivle</button>
      </form>`;

  return `<article class="card ${archived ? "archived" : "inbox"}">
    <input class="card-select ${checkboxClass}" type="checkbox" name="ids" value="${escapeHtml(item.commentId)}" form="${formId}">
    <div class="card-body">
      <div class="card-head">
        <div class="identity">@${escapeHtml(item.username || "kullanıcı-adı-yok")}</div>
        <div class="time">${escapeHtml(formatDate(item.eventTime || item.firstReceivedAt))}</div>
      </div>
      <div class="text">${escapeHtml(item.text || "(Boş yorum)")}</div>
      ${parentPreview}
      <div class="meta">
        ${archived ? '<span class="pill archive">Arşiv</span>' : '<span class="pill good">Gelen kutusu</span>'}
        <span class="pill ${item.isReply ? "warn" : "good"}">${item.isReply ? "Yanıt" : "Ana yorum"}</span>
        <span class="pill">${escapeHtml(item.mediaProductType || "Medya türü yok")}</span>
        <span class="pill">Medya: ${escapeHtml(item.mediaId || "—")}</span>
      </div>
      <div class="actions">
        ${stateAction}
        <form method="post" action="/panel/comments/${encodeURIComponent(item.commentId)}/delete" onsubmit="return confirm('Bu yorum veritabanından kalıcı olarak silinecek. Geri alınamaz. Emin misin?');">
          <input type="hidden" name="csrf" value="${PANEL_CSRF_TOKEN}">
          <input type="hidden" name="returnTo" value="${escapeHtml(returnTo)}">
          <button class="button-danger" type="submit">Kalıcı sil</button>
        </form>
      </div>
      <details>
        <summary>Teknik bilgiler</summary>
        <div>Yorum ID: ${escapeHtml(item.commentId)}</div>
        <div>Yazar ID: ${escapeHtml(item.authorId || "—")}</div>
        <div>Ana yorum ID: ${escapeHtml(item.parentCommentId || "—")}</div>
        <div>Durum: ${escapeHtml(item.status || "inbox")}</div>
      </details>
    </div>
  </article>`;
}

function messageCard({ item, archived, returnTo, formId, checkboxClass }) {
  const attachmentCount = Array.isArray(item.attachments) ? item.attachments.length : 0;
  const deleted = item.isDeleted ? "(Silinmiş mesaj)" : null;
  const body = item.text || deleted || (attachmentCount ? `[${attachmentCount} ek]` : "(Metinsiz mesaj)");

  const stateAction = archived
    ? `<form method="post" action="/panel/messages/${encodeURIComponent(item.mid)}/restore">
        <input type="hidden" name="csrf" value="${PANEL_CSRF_TOKEN}">
        <input type="hidden" name="returnTo" value="${escapeHtml(returnTo)}">
        <button class="button-secondary" type="submit">↩ Gelen kutusuna taşı</button>
      </form>`
    : `<form method="post" action="/panel/messages/${encodeURIComponent(item.mid)}/archive">
        <input type="hidden" name="csrf" value="${PANEL_CSRF_TOKEN}">
        <input type="hidden" name="returnTo" value="${escapeHtml(returnTo)}">
        <button class="button-archive" type="submit">Arşivle</button>
      </form>`;

  return `<article class="card ${archived ? "archived" : "inbox"}">
    <input class="card-select ${checkboxClass}" type="checkbox" name="ids" value="${escapeHtml(item.mid)}" form="${formId}">
    <div class="card-body">
      <div class="card-head">
        <div class="identity">${item.direction === "incoming" ? "Gelen DM" : "Gönderilen DM"}</div>
        <div class="time">${escapeHtml(formatDate(item.eventTime || item.firstReceivedAt))}</div>
      </div>
      <div class="text">${escapeHtml(body)}</div>
      <div class="meta">
        ${archived ? '<span class="pill archive">Arşiv</span>' : '<span class="pill good">Gelen kutusu</span>'}
        <span class="pill ${item.direction === "incoming" ? "good" : "warn"}">${item.direction === "incoming" ? "Gelen" : "Giden"}</span>
        ${attachmentCount ? `<span class="pill">${attachmentCount} ek</span>` : ""}
        ${item.isDeleted ? '<span class="pill warn">Silinmiş</span>' : ""}
        ${item.replyTo ? '<span class="pill">Yanıt</span>' : ""}
      </div>
      <div class="actions">
        ${stateAction}
        <form method="post" action="/panel/messages/${encodeURIComponent(item.mid)}/delete" onsubmit="return confirm('Bu DM veritabanından kalıcı olarak silinecek. Geri alınamaz. Emin misin?');">
          <input type="hidden" name="csrf" value="${PANEL_CSRF_TOKEN}">
          <input type="hidden" name="returnTo" value="${escapeHtml(returnTo)}">
          <button class="button-danger" type="submit">Kalıcı sil</button>
        </form>
      </div>
      <details>
        <summary>Teknik bilgiler</summary>
        <div>Mesaj ID: ${escapeHtml(item.mid)}</div>
        <div>Gönderen ID: ${escapeHtml(item.senderId || "—")}</div>
        <div>Alıcı ID: ${escapeHtml(item.recipientId || "—")}</div>
        <div>Durum: ${escapeHtml(item.status || "inbox")}</div>
      </details>
    </div>
  </article>`;
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

async function renderCommentsPage(req, res, next, archived) {
  try {
    const page = clampInteger(req.query.page, 1, 100000, 1);
    const limit = clampInteger(req.query.limit, 10, 100, 50);
    const q = String(req.query.q || "").trim().slice(0, 200);
    const type = ["all", "main", "reply"].includes(req.query.type)
      ? req.query.type
      : "all";
    const basePath = archived ? "/panel/comments/archive" : "/panel/comments";
    const filter = { status: archived ? "archived" : "inbox" };

    if (type === "main") filter.isReply = false;
    if (type === "reply") filter.isReply = true;

    if (q) {
      const regex = new RegExp(escapeRegex(q), "i");
      filter.$or = [
        { text: regex },
        { username: regex },
        { commentId: regex },
        { authorId: regex },
        { mediaId: regex },
      ];
    }

    const [total, stats] = await Promise.all([
      Comment.countDocuments(filter),
      getStats(),
    ]);

    const pages = Math.max(1, Math.ceil(total / limit));
    const safePage = Math.min(page, pages);
    const items = await Comment.find(filter)
      .sort({ eventTime: -1, firstReceivedAt: -1, _id: -1 })
      .skip((safePage - 1) * limit)
      .limit(limit)
      .lean();

    const parentIds = Array.from(
      new Set(items.map((item) => item.parentCommentId).filter(Boolean))
    );
    const parents = parentIds.length
      ? await Comment.find({ commentId: { $in: parentIds } }).lean()
      : [];
    const parentMap = new Map(parents.map((item) => [item.commentId, item]));
    const returnTo = `${basePath}${encodeQuery({ q, type, limit, page: safePage })}`;
    const formId = archived ? "bulk-comment-archive" : "bulk-comment-inbox";
    const checkboxClass = archived ? "comment-archive-box" : "comment-inbox-box";

    const cards = items.length
      ? items.map((item) => commentCard({
          item,
          archived,
          parent: item.parentCommentId ? parentMap.get(item.parentCommentId) : null,
          returnTo,
          formId,
          checkboxClass,
        })).join("")
      : `<div class="empty">${archived ? "Arşivlenmiş yorum bulunamadı." : "Gelen kutusunda yorum kalmadı."}</div>`;

    const content = `
      ${noticeHtml(String(req.query.notice || ""))}
      <div class="page-title">
        <div><h1>${archived ? "Arşivlenen yorumlar" : "Yorumlar"}</h1><p>${archived ? "Saklamak istediğin yorumlar burada durur." : "Yeni yorumlar burada bekler; arşivle veya kalıcı sil."}</p></div>
      </div>
      <form class="toolbar" method="get" action="${basePath}">
        <input type="search" name="q" value="${escapeHtml(q)}" placeholder="Yorum, kullanıcı adı veya ID ara">
        <select name="type">
          <option value="all" ${type === "all" ? "selected" : ""}>Tüm yorum türleri</option>
          <option value="main" ${type === "main" ? "selected" : ""}>Ana yorumlar</option>
          <option value="reply" ${type === "reply" ? "selected" : ""}>Yanıtlar</option>
        </select>
        <select name="limit">
          ${[25, 50, 100].map((value) => `<option value="${value}" ${limit === value ? "selected" : ""}>${value} / sayfa</option>`).join("")}
        </select>
        <button type="submit">Filtrele</button>
      </form>
      ${items.length ? bulkBar({ formId, endpoint: "/panel/comments/bulk", returnTo, archived, checkboxClass }) : ""}
      <div class="list">${cards}</div>
      ${paginationHtml({ page: safePage, pages, basePath, params: { q, type, limit } })}`;

    return res.status(200).send(layout({
      title: archived ? "Arşivlenen yorumlar" : "Yorumlar",
      active: archived ? "commentArchive" : "comments",
      stats,
      content,
    }));
  } catch (error) {
    return next(error);
  }
}

app.get("/panel/comments", (req, res, next) => renderCommentsPage(req, res, next, false));
app.get("/panel/comments/archive", (req, res, next) => renderCommentsPage(req, res, next, true));

app.post("/panel/comments/:commentId/archive", async (req, res, next) => {
  try {
    if (!verifyPanelCsrf(req)) return res.status(403).send("Geçersiz panel isteği.");
    await Comment.updateOne(
      { commentId: String(req.params.commentId || "") },
      { $set: { status: "archived", statusUpdatedAt: new Date() } }
    );
    return redirectWithNotice(res, req.body.returnTo, "archived");
  } catch (error) { return next(error); }
});

app.post("/panel/comments/:commentId/restore", async (req, res, next) => {
  try {
    if (!verifyPanelCsrf(req)) return res.status(403).send("Geçersiz panel isteği.");
    await Comment.updateOne(
      { commentId: String(req.params.commentId || "") },
      { $set: { status: "inbox", statusUpdatedAt: new Date() } }
    );
    return redirectWithNotice(res, req.body.returnTo, "restored");
  } catch (error) { return next(error); }
});

app.post("/panel/comments/:commentId/delete", async (req, res, next) => {
  try {
    if (!verifyPanelCsrf(req)) return res.status(403).send("Geçersiz panel isteği.");
    const commentId = String(req.params.commentId || "");
    const item = await Comment.findOneAndDelete({ commentId });
    if (item) await removeCommentFromRawEvent(item.rawEventId, commentId);
    return redirectWithNotice(res, req.body.returnTo, "deleted");
  } catch (error) { return next(error); }
});

app.post("/panel/comments/bulk", async (req, res, next) => {
  try {
    if (!verifyPanelCsrf(req)) return res.status(403).send("Geçersiz panel isteği.");
    const ids = selectedValues(req.body.ids);
    const action = String(req.body.action || "");
    if (!ids.length) return redirectWithNotice(res, req.body.returnTo, "nothing-selected");

    if (action === "archive" || action === "restore") {
      const status = action === "archive" ? "archived" : "inbox";
      await Comment.updateMany(
        { commentId: { $in: ids } },
        { $set: { status, statusUpdatedAt: new Date() } }
      );
      return redirectWithNotice(res, req.body.returnTo, action === "archive" ? "bulk-archived" : "bulk-restored");
    }

    if (action === "delete") {
      const items = await Comment.find({ commentId: { $in: ids } }).lean();
      await Comment.deleteMany({ commentId: { $in: ids } });
      for (const item of items) {
        await removeCommentFromRawEvent(item.rawEventId, item.commentId);
      }
      return redirectWithNotice(res, req.body.returnTo, "bulk-deleted");
    }

    return res.status(400).send("Geçersiz toplu işlem.");
  } catch (error) { return next(error); }
});

async function renderMessagesPage(req, res, next, archived) {
  try {
    const page = clampInteger(req.query.page, 1, 100000, 1);
    const limit = clampInteger(req.query.limit, 10, 100, 50);
    const q = String(req.query.q || "").trim().slice(0, 200);
    const direction = ["all", "incoming", "outgoing"].includes(req.query.direction)
      ? req.query.direction
      : "all";
    const basePath = archived ? "/panel/messages/archive" : "/panel/messages";
    const filter = { status: archived ? "archived" : "inbox" };

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

    const [total, stats] = await Promise.all([
      Message.countDocuments(filter),
      getStats(),
    ]);
    const pages = Math.max(1, Math.ceil(total / limit));
    const safePage = Math.min(page, pages);
    const items = await Message.find(filter)
      .sort({ eventTime: -1, firstReceivedAt: -1, _id: -1 })
      .skip((safePage - 1) * limit)
      .limit(limit)
      .lean();

    const returnTo = `${basePath}${encodeQuery({ q, direction, limit, page: safePage })}`;
    const formId = archived ? "bulk-message-archive" : "bulk-message-inbox";
    const checkboxClass = archived ? "message-archive-box" : "message-inbox-box";
    const cards = items.length
      ? items.map((item) => messageCard({ item, archived, returnTo, formId, checkboxClass })).join("")
      : `<div class="empty">${archived ? "Arşivlenmiş DM bulunamadı." : "Gelen kutusunda DM kalmadı."}</div>`;

    const content = `
      ${noticeHtml(String(req.query.notice || ""))}
      <div class="page-title">
        <div><h1>${archived ? "Arşivlenen DM’ler" : "DM’ler"}</h1><p>${archived ? "Saklamak istediğin mesajlar burada durur." : "Mesajları arşivle veya veritabanından kalıcı sil."}</p></div>
      </div>
      <form class="toolbar" method="get" action="${basePath}">
        <input type="search" name="q" value="${escapeHtml(q)}" placeholder="Mesaj metni veya ID ara">
        <select name="direction">
          <option value="all" ${direction === "all" ? "selected" : ""}>Tümü</option>
          <option value="incoming" ${direction === "incoming" ? "selected" : ""}>Gelenler</option>
          <option value="outgoing" ${direction === "outgoing" ? "selected" : ""}>Gönderilenler</option>
        </select>
        <select name="limit">
          ${[25, 50, 100].map((value) => `<option value="${value}" ${limit === value ? "selected" : ""}>${value} / sayfa</option>`).join("")}
        </select>
        <button type="submit">Filtrele</button>
      </form>
      ${items.length ? bulkBar({ formId, endpoint: "/panel/messages/bulk", returnTo, archived, checkboxClass }) : ""}
      <div class="list">${cards}</div>
      ${paginationHtml({ page: safePage, pages, basePath, params: { q, direction, limit } })}`;

    return res.status(200).send(layout({
      title: archived ? "Arşivlenen DM’ler" : "DM’ler",
      active: archived ? "messageArchive" : "messages",
      stats,
      content,
    }));
  } catch (error) {
    return next(error);
  }
}

app.get("/panel/messages", (req, res, next) => renderMessagesPage(req, res, next, false));
app.get("/panel/messages/archive", (req, res, next) => renderMessagesPage(req, res, next, true));

app.post("/panel/messages/:mid/archive", async (req, res, next) => {
  try {
    if (!verifyPanelCsrf(req)) return res.status(403).send("Geçersiz panel isteği.");
    await Message.updateOne(
      { mid: String(req.params.mid || "") },
      { $set: { status: "archived", statusUpdatedAt: new Date() } }
    );
    return redirectWithNotice(res, req.body.returnTo, "archived");
  } catch (error) { return next(error); }
});

app.post("/panel/messages/:mid/restore", async (req, res, next) => {
  try {
    if (!verifyPanelCsrf(req)) return res.status(403).send("Geçersiz panel isteği.");
    await Message.updateOne(
      { mid: String(req.params.mid || "") },
      { $set: { status: "inbox", statusUpdatedAt: new Date() } }
    );
    return redirectWithNotice(res, req.body.returnTo, "restored");
  } catch (error) { return next(error); }
});

app.post("/panel/messages/:mid/delete", async (req, res, next) => {
  try {
    if (!verifyPanelCsrf(req)) return res.status(403).send("Geçersiz panel isteği.");
    const mid = String(req.params.mid || "");
    const item = await Message.findOneAndDelete({ mid });
    if (item) await removeMessageFromRawEvent(item.rawEventId, mid);
    return redirectWithNotice(res, req.body.returnTo, "deleted");
  } catch (error) { return next(error); }
});

app.post("/panel/messages/bulk", async (req, res, next) => {
  try {
    if (!verifyPanelCsrf(req)) return res.status(403).send("Geçersiz panel isteği.");
    const ids = selectedValues(req.body.ids);
    const action = String(req.body.action || "");
    if (!ids.length) return redirectWithNotice(res, req.body.returnTo, "nothing-selected");

    if (action === "archive" || action === "restore") {
      const status = action === "archive" ? "archived" : "inbox";
      await Message.updateMany(
        { mid: { $in: ids } },
        { $set: { status, statusUpdatedAt: new Date() } }
      );
      return redirectWithNotice(res, req.body.returnTo, action === "archive" ? "bulk-archived" : "bulk-restored");
    }

    if (action === "delete") {
      const items = await Message.find({ mid: { $in: ids } }).lean();
      await Message.deleteMany({ mid: { $in: ids } });
      for (const item of items) {
        await removeMessageFromRawEvent(item.rawEventId, item.mid);
      }
      return redirectWithNotice(res, req.body.returnTo, "bulk-deleted");
    }

    return res.status(400).send("Geçersiz toplu işlem.");
  } catch (error) { return next(error); }
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
      <section class="card"><div class="identity">Bağlantı durumu</div><div class="meta">
        <span class="pill good">Node.js çalışıyor</span>
        <span class="pill ${mongoose.connection.readyState === 1 ? "good" : "warn"}">MongoDB ${mongoose.connection.readyState === 1 ? "bağlı" : "bağlı değil"}</span>
        <span class="pill good">İmza doğrulaması aktif</span>
        <span class="pill good">Ham kayıtlar ${RAW_EVENT_RETENTION_DAYS} gün saklanır</span>
      </div></section>
      <section class="card"><div class="identity">Son hareketler</div><div class="code">
        Son webhook: ${escapeHtml(formatDate(lastWebhook?.receivedAt))}<br>
        Son yorum: ${escapeHtml(formatDate(lastComment?.eventTime || lastComment?.firstReceivedAt))}<br>
        Son DM: ${escapeHtml(formatDate(lastMessage?.eventTime || lastMessage?.firstReceivedAt))}
      </div></section>
    </div>`;

    return res.status(200).send(layout({ title: "Sistem", active: "status", stats, content }));
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

    let rawEvent = await WebhookEvent.findOne({ eventHash });

    if (rawEvent?.processedAt) {
      console.log(`Tekrarlanan webhook yok sayıldı | tür=${eventTypes.join(",") || "bilinmiyor"}`);
      return res.status(200).send("EVENT_RECEIVED");
    }

    if (!rawEvent) {
      try {
        rawEvent = await WebhookEvent.create({
          eventHash,
          object: body.object || null,
          accountIds,
          eventTypes,
          payload: body,
          receivedAt: new Date(),
          processedAt: null,
          expiresAt: new Date(Date.now() + RAW_EVENT_TTL_MS),
        });
      } catch (error) {
        if (error?.code === 11000) {
          rawEvent = await WebhookEvent.findOne({ eventHash });
          if (rawEvent?.processedAt) {
            return res.status(200).send("EVENT_RECEIVED");
          }
        } else {
          throw error;
        }
      }
    }

    if (!rawEvent) throw new Error("Ham webhook kaydı oluşturulamadı.");

    const result = await normalizeWebhook(body, rawEvent._id);
    rawEvent.processedAt = new Date();
    await rawEvent.save();

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

async function runMigrations() {
  const now = new Date();

  // v1.1'deki "unread" ve "reviewed" kayıtları karar verilmesi için gelen kutusuna döner.
  await Comment.updateMany(
    { status: { $nin: ["inbox", "archived"] } },
    { $set: { status: "inbox", statusUpdatedAt: now } }
  );

  await Message.updateMany(
    { status: { $nin: ["inbox", "archived"] } },
    { $set: { status: "inbox", statusUpdatedAt: now } }
  );

  await WebhookEvent.updateMany(
    { processedAt: { $exists: false } },
    { $set: { processedAt: now } }
  );

  await WebhookEvent.updateMany(
    { expiresAt: { $exists: false } },
    { $set: { expiresAt: new Date(Date.now() + RAW_EVENT_TTL_MS) } }
  );

  await WebhookEvent.collection.createIndex(
    { expiresAt: 1 },
    { expireAfterSeconds: 0, name: "expiresAt_ttl" }
  );
}

mongoose
  .connect(MONGO_URL)
  .then(async () => {
    console.log("MongoDB bağlantısı başarılı.");
    await runMigrations();
    console.log(`Panel v1.2 hazır. Ham webhook saklama süresi: ${RAW_EVENT_RETENTION_DAYS} gün.`);
    app.listen(PORT, () => {
      console.log(`Sunucu ${PORT} portunda çalışıyor.`);
    });
  })
  .catch((error) => {
    console.error("MongoDB bağlantı/başlatma hatası:", error);
    process.exit(1);
  });
