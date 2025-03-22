const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path'); // ✅ Required for static file support

const app = express();
const PORT = process.env.PORT || 3000;

const VT_API_KEY = '37245157627c004794c63aa38d7636914bad23b6a52ad21b2770b10ba0d06d4f';

// ✅ Middleware
app.use(cors());
app.use(express.json());

// ✅ Serve static frontend files from the public folder
app.use(express.static(path.join(__dirname, 'public')));

// ✅ POST /scan route for frontend to use
app.post('/scan', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'Missing URL in request body' });

  try {
    // Step 1: Submit URL to VirusTotal
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

    // Step 2: Wait and then get report
    setTimeout(async () => {
      try {
        const reportResponse = await axios.get(
          `https://www.virustotal.com/api/v3/analyses/${scanId}`,
          {
            headers: { 'x-apikey': VT_API_KEY }
          }
        );
        res.json(reportResponse.data);
      } catch (err) {
        console.error('Error retrieving report:', err.message);
        res.status(500).json({ error: 'Failed to retrieve scan report' });
      }
    }, 3000);
  } catch (err) {
    console.error('Error submitting scan:', err.message);
    res.status(500).json({ error: 'Failed to submit scan' });
  }
});

// ✅ Start the server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
