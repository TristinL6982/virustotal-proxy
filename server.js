const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const VT_API_KEY = '37245157627c004794c63aa38d7636914bad23b6a52ad21b2770b10ba0d06d4f';

app.use(cors());
app.use(express.json());

// ✅ THIS MUST COME BEFORE /scan
app.use(express.static(path.join(__dirname, 'public')));

// VirusTotal scan route
app.post('/scan', async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'Missing URL in request body' });
  }

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

    setTimeout(async () => {
      try {
        const reportResponse = await axios.get(
          `https://www.virustotal.com/api/v3/analyses/${scanId}`,
          {
            headers: { 'x-apikey': VT_API_KEY },
          }
        );

        res.json(reportResponse.data);
      } catch (error) {
        console.error('Error retrieving scan report:', error.message);
        res.status(500).json({ error: 'Failed to retrieve scan report' });
      }
    }, 3000);
  } catch (error) {
    console.error('Error submitting scan:', error.message);
    res.status(500).json({ error: 'Failed to submit scan' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
