const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');

const app = express();
app.use(bodyParser.json());

const mongoUrl = process.env.MONGO_URL;
mongoose.connect(mongoUrl)
  .then(() => console.log('MongoDB baglantisi basarili!'))
  .catch(err => console.error('MongoDB hatasi:', err));

const WebhookSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  body: Object
});
const WebhookLog = mongoose.model('WebhookLog', WebhookSchema);

app.get('/webhook', (req, res) => {
  const VERIFY_TOKEN = process.env.VERIFY_TOKEN || "b1rmod_token";
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode && token) {
    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
      console.log('Webhook dogrulandi.');
      res.status(200).send(challenge);
    } else {
      res.sendStatus(403);
    }
  }
});

// Gelen her şeyi direkt yakala ve kaydet
app.post('/webhook', async (req, res) => {
  console.log('Gelen İstek:', JSON.stringify(req.body));
  try {
    await WebhookLog.create({ body: req.body });
    console.log('Yeni veri basariyla MongoDB ye kaydedildi!');
  } catch (error) {
    console.error('Kayit hatasi:', error);
  }
  res.status(200).send('EVENT_RECEIVED');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sunucu port ${PORT} uzerinde calisiyor.`));
