// server.js
const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const VT_API_KEY = '37245157627c004794c63aa38d7636914bad23b6a52ad21b2770b10ba0d06d4f';

app.post('/scan', async (req, res) => {
  try {
    const { url } = req.body;

    // Step 1: Submit the URL to VirusTotal
    const scanResponse = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      new URLSearchParams({ url }),
      {
        headers: {
          'x-apikey': VT_API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const scanId = scanResponse.data.data.id;

    // Step 2: Get the report
    setTimeout(async () => {
      try {
        const reportResponse = await axios.get(
          `https://www.virustotal.com/api/v3/analyses/${scanId}`,
          {
            headers: {
              'x-apikey': VT_API_KEY
            }
          }
        );

        res.json(reportResponse.data);
      } catch (err) {
        res.status(500).json({ error: 'Failed to get report.' });
      }
    }, 3000); // wait 3 seconds
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: 'Scan failed.' });
  }
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
