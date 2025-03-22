const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const dns = require('dns').promises;

const app = express();
const PORT = process.env.PORT || 3000;

const VT_API_KEY = '37245157627c004794c63aa38d7636914bad23b6a52ad21b2770b10ba0d06d4f';
const ABUSE_IP_KEY = '54014bb2293bc998ac3792bfc12c7a6c59caa50f0e81e5bbe697b56399d0036a50237789a7882672';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/abuseipdb', async (req, res) => {
  const { ip } = req.body;

  try {
    const addresses = await dns.lookup(ip);
    const ipAddress = addresses.address;

    const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      params: {
        ipAddress,
        maxAgeInDays: 90
      },
      headers: {
        Key: ABUSE_IP_KEY,
        Accept: 'application/json'
      }
    });

    res.json(response.data.data);
  } catch (error) {
    res.status(500).json({ error: 'AbuseIPDB request failed' });
  }
});
