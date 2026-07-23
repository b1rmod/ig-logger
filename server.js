const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');

const app = express();
app.use(bodyParser.json());

// Veritabanı bağlantısı (Link Coolify'dan gelecek)
const mongoUrl = process.env.MONGO_URL;
mongoose.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB baglantisi basarili!'))
  .catch(err => console.error('MongoDB hatasi:', err));

// Gelen her şeyi tutacak esnek şema
const WebhookSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  body: Object
});
const WebhookLog = mongoose.model('WebhookLog', WebhookSchema);

// Meta'nın güvenlik doğrulaması
app.get('/webhook', (req, res) => {
  const VERIFY_TOKEN = process.env.VERIFY_TOKEN || "benim_gizli_tokenim";
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode && token) {
    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
      console.log('Webhook Meta tarafindan dogrulandi.');
      res.status(200).send(challenge);
    } else {
      res.sendStatus(403);
    }
  }
});

// Instagram verilerini yakalayıp veritabanına yazma
app.post('/webhook', async (req, res) => {
  const body = req.body;
  
  if (body.object === 'instagram') {
    try {
      await WebhookLog.create({ body: body });
      console.log('Yeni veri basariyla MongoDB ye kaydedildi!');
    } catch (error) {
      console.error('Veritabani kayit hatasi:', error);
    }
    res.status(200).send('EVENT_RECEIVED');
  } else {
    res.sendStatus(404);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sunucu port ${PORT} uzerinde calisiyor.`));
