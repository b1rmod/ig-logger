const crypto = require("crypto");
const express = require("express");
const mongoose = require("mongoose");

const app = express();

app.use(
  express.json({
    limit: "2mb",
    verify: (req, res, buffer) => {
      req.rawBody = Buffer.from(buffer);
    },
  })
);

const {
  MONGO_URL,
  VERIFY_TOKEN,
  APP_SECRET,
  PORT = 3000,
} = process.env;

if (!MONGO_URL) {
  throw new Error("MONGO_URL çevre değişkeni eksik.");
}

if (!VERIFY_TOKEN) {
  throw new Error("VERIFY_TOKEN çevre değişkeni eksik.");
}

if (!APP_SECRET) {
  console.warn(
    "UYARI: APP_SECRET tanımlı değil. Webhook imza doğrulaması yapılmayacak."
  );
}

/* -------------------------------------------------------------------------- */
/* MongoDB şemaları                                                           */
/* -------------------------------------------------------------------------- */

const webhookEventSchema = new mongoose.Schema(
  {
    eventHash: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },

    object: {
      type: String,
      default: null,
    },

    accountIds: {
      type: [String],
      default: [],
    },

    eventTypes: {
      type: [String],
      default: [],
    },

    payload: {
      type: mongoose.Schema.Types.Mixed,
      required: true,
    },

    receivedAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
  },
  {
    versionKey: false,
    collection: "webhook_events",
  }
);

const commentSchema = new mongoose.Schema(
  {
    commentId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },

    accountId: {
      type: String,
      required: true,
      index: true,
    },

    authorId: {
      type: String,
      default: null,
      index: true,
    },

    username: {
      type: String,
      default: null,
      index: true,
    },

    mediaId: {
      type: String,
      default: null,
      index: true,
    },

    mediaProductType: {
      type: String,
      default: null,
    },

    parentCommentId: {
      type: String,
      default: null,
      index: true,
    },

    isReply: {
      type: Boolean,
      default: false,
      index: true,
    },

    text: {
      type: String,
      default: "",
    },

    eventTime: {
      type: Date,
      default: null,
      index: true,
    },

    firstReceivedAt: {
      type: Date,
      default: Date.now,
    },

    lastReceivedAt: {
      type: Date,
      default: Date.now,
    },

    rawEventId: {
      type: mongoose.Schema.Types.ObjectId,
      default: null,
    },
  },
  {
    versionKey: false,
    collection: "comments",
  }
);

const messageSchema = new mongoose.Schema(
  {
    mid: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },

    accountId: {
      type: String,
      required: true,
      index: true,
    },

    senderId: {
      type: String,
      default: null,
      index: true,
    },

    recipientId: {
      type: String,
      default: null,
      index: true,
    },

    direction: {
      type: String,
      enum: ["incoming", "outgoing"],
      required: true,
      index: true,
    },

    text: {
      type: String,
      default: null,
    },

    attachments: {
      type: Array,
      default: [],
    },

    replyTo: {
      type: mongoose.Schema.Types.Mixed,
      default: null,
    },

    isSelf: {
      type: Boolean,
      default: false,
    },

    isEcho: {
      type: Boolean,
      default: false,
    },

    isDeleted: {
      type: Boolean,
      default: false,
    },

    folder: {
      type: String,
      default: null,
    },

    eventTime: {
      type: Date,
      default: null,
      index: true,
    },

    firstReceivedAt: {
      type: Date,
      default: Date.now,
    },

    lastReceivedAt: {
      type: Date,
      default: Date.now,
    },

    rawEventId: {
      type: mongoose.Schema.Types.ObjectId,
      default: null,
    },
  },
  {
    versionKey: false,
    collection: "messages",
  }
);

const WebhookEvent = mongoose.model("WebhookEvent", webhookEventSchema);
const Comment = mongoose.model("Comment", commentSchema);
const Message = mongoose.model("Message", messageSchema);

/* -------------------------------------------------------------------------- */
/* Yardımcı fonksiyonlar                                                      */
/* -------------------------------------------------------------------------- */

function toDate(value) {
  if (value === null || value === undefined) {
    return null;
  }

  const number = Number(value);

  if (!Number.isFinite(number)) {
    return null;
  }

  // Instagram bazı yerlerde saniye, bazı yerlerde milisaniye gönderiyor.
  return new Date(number < 1_000_000_000_000 ? number * 1000 : number);
}

function verifyMetaSignature(req) {
  // APP_SECRET henüz tanımlanmadıysa geçici olarak doğrulamayı atlar.
  if (!APP_SECRET) {
    return true;
  }

  const receivedSignature = req.get("x-hub-signature-256");

  if (!receivedSignature || !req.rawBody) {
    return false;
  }

  const expectedSignature =
    "sha256=" +
    crypto
      .createHmac("sha256", APP_SECRET)
      .update(req.rawBody)
      .digest("hex");

  const receivedBuffer = Buffer.from(receivedSignature);
  const expectedBuffer = Buffer.from(expectedSignature);

  if (receivedBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(receivedBuffer, expectedBuffer);
}

function detectEventTypes(body) {
  const types = new Set();

  for (const entry of body.entry || []) {
    for (const change of entry.changes || []) {
      if (change.field) {
        types.add(change.field);
      }
    }

    for (const messagingEvent of entry.messaging || []) {
      if (messagingEvent.message) {
        types.add("messages");
      }

      if (messagingEvent.read) {
        types.add("messaging_seen");
      }

      if (messagingEvent.reaction) {
        types.add("message_reactions");
      }

      if (messagingEvent.postback) {
        types.add("messaging_postbacks");
      }
    }
  }

  return Array.from(types);
}

async function normalizeWebhook(body, rawEventId) {
  const commentOperations = [];
  const messageOperations = [];

  for (const entry of body.entry || []) {
    const accountId = String(entry.id || "");

    /* ------------------------------ Yorumlar ------------------------------ */

    for (const change of entry.changes || []) {
      if (change.field !== "comments") {
        continue;
      }

      const value = change.value || {};

      if (!value.id) {
        continue;
      }

      const commentId = String(value.id);
      const parentCommentId = value.parent_id
        ? String(value.parent_id)
        : null;

      commentOperations.push({
        updateOne: {
          filter: {
            commentId,
          },

          update: {
            $set: {
              accountId,
              authorId: value.from?.id
                ? String(value.from.id)
                : null,
              username: value.from?.username || null,
              mediaId: value.media?.id
                ? String(value.media.id)
                : null,
              mediaProductType:
                value.media?.media_product_type || null,
              parentCommentId,
              isReply: Boolean(parentCommentId),
              text: value.text || "",
              eventTime: toDate(entry.time),
              lastReceivedAt: new Date(),
            },

            $setOnInsert: {
              firstReceivedAt: new Date(),
              rawEventId,
            },
          },

          upsert: true,
        },
      });
    }

    /* ------------------------------- DM'ler ------------------------------- */

    for (const messagingEvent of entry.messaging || []) {
      const message = messagingEvent.message;

      // Görüldü gibi mesaj olmayan olayları burada bilerek almıyoruz.
      if (!message?.mid) {
        continue;
      }

      const senderId = messagingEvent.sender?.id
        ? String(messagingEvent.sender.id)
        : null;

      const recipientId = messagingEvent.recipient?.id
        ? String(messagingEvent.recipient.id)
        : null;

      const direction =
        message.is_self === true || senderId === accountId
          ? "outgoing"
          : "incoming";

      messageOperations.push({
        updateOne: {
          filter: {
            mid: String(message.mid),
          },

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
              eventTime: toDate(
                messagingEvent.timestamp || entry.time
              ),
              lastReceivedAt: new Date(),
            },

            $setOnInsert: {
              firstReceivedAt: new Date(),
              rawEventId,
            },
          },

          upsert: true,
        },
      });
    }
  }

  if (commentOperations.length > 0) {
    await Comment.bulkWrite(commentOperations, {
      ordered: false,
    });
  }

  if (messageOperations.length > 0) {
    await Message.bulkWrite(messageOperations, {
      ordered: false,
    });
  }

  return {
    comments: commentOperations.length,
    messages: messageOperations.length,
  };
}

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
    const eventTypes = detectEventTypes(body);

    const eventHash = crypto
      .createHash("sha256")
      .update(req.rawBody || JSON.stringify(body))
      .digest("hex");

    const accountIds = (body.entry || [])
      .map((entry) => String(entry.id || ""))
      .filter(Boolean);

    const rawEvent = await WebhookEvent.findOneAndUpdate(
      {
        eventHash,
      },
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
      {
        upsert: true,
        new: true,
        setDefaultsOnInsert: true,
      }
    );

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
    console.error("Webhook işleme hatası:", error);
    return res.status(500).send("WEBHOOK_ERROR");
  }
});

app.get("/health", (req, res) => {
  return res.status(200).json({
    status: "ok",
    mongodb:
      mongoose.connection.readyState === 1
        ? "connected"
        : "disconnected",
    time: new Date().toISOString(),
  });
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
