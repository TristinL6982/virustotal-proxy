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

// VIRUSTOTAL ROUTE
app.post('/api/virustotal', async (req, res) => {
  const { url } = req.body;
  console.log('[VirusTotal] URL received:', url);

  try {
    const scanResponse = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      new URLSearchParams({ url }),
      {
        headers: {
          'x-apikey': VT_API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }
    );

    const scanId = scanResponse.data.data.id;
    console.log('[VirusTotal] Scan submitted, ID:', scanId);

    setTimeout(async () => {
      try {
        const reportResponse = await axios.get(
          `https://www.virustotal.com/api/v3/analyses/${scanId}`,
          {
            headers: { 'x-apikey': VT_API_KEY },
          }
        );
        console.log('[VirusTotal] Scan report retrieved.');
        res.json(reportResponse.data);
      } catch (error) {
        console.error('[VirusTotal] Error retrieving scan report:', error.message);
        res.status(500).json({ error: 'Failed to retrieve scan report' });
      }
    }, 3000);
  } catch (error) {
    console.error('[VirusTotal] Error submitting scan:', error.message);
    res.status(500).json({ error: 'Failed to submit scan' });
  }
});

// ABUSEIPDB ROUTE
app.post('/api/abuseipdb', async (req, res) => {
  const { ip } = req.body;
  console.log('[AbuseIPDB] Domain received for lookup:', ip);

  try {
    const addresses = await dns.lookup(ip, { all: true });
    const ipAddress = addresses[0]?.address;
    console.log('[AbuseIPDB] Resolved IP:', ipAddress);

    if (!ipAddress) {
      console.error('[AbuseIPDB] IP resolution failed.');
      return res.status(400).json({ error: 'Failed to resolve IP from domain' });
    }

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

    console.log('[AbuseIPDB] Abuse data retrieved for IP.');
    res.json(response.data.data);
  } catch (error) {
    console.error('[AbuseIPDB] Request failed:', error.message);
    res.status(500).json({ error: 'AbuseIPDB request failed' });
  }
});

// FALLBACK FOR 404
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
