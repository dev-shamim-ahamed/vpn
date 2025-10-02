// net.js
// Simple VPN detection - Shows only "✅ Real User" or "🚫 VPN User"
// - Place GeoLite2-ASN.mmdb in ./db/
// - npm install express maxmind cors
// - node net.js
// - Visit http://localhost:3000

import express from "express";
import maxmind from "maxmind";
import path from "path";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

const DB_PATH = path.join(process.cwd(), "db", "GeoLite2-ASN.mmdb");

// Load MaxMind DB
let lookup = null;
maxmind.open(DB_PATH)
  .then((l) => {
    lookup = l;
    console.log("✅ GeoLite2 ASN DB loaded");
  })
  .catch((err) => {
    console.error("❌ Failed to load GeoLite2 DB:", err);
  });

// VPN detection
function isVPN(asnInfo) {
  if (!asnInfo) return false;
  
  const org = (asnInfo.autonomous_system_organization || "").toLowerCase();
  
  const vpnKeywords = [
    "vpn", "proxy", "hosting", "datacenter", "cloud",
    "expressvpn", "nordvpn", "surfshark", "cyberghost", 
    "private internet access", "ipvanish", "vyprvpn",
    "windscribe", "tunnelbear", "protonvpn", "mullvad",
    "amazon", "aws", "digitalocean", "ovh", "hetzner",
    "google cloud", "microsoft", "azure", "linode"
  ];

  return vpnKeywords.some(keyword => org.includes(keyword));
}

// Normalize IP
function normalizeIp(ipRaw) {
  if (!ipRaw) return null;
  let ip = ipRaw;
  if (ip.includes(",")) ip = ip.split(",")[0].trim();
  if (ip.startsWith("::ffff:")) ip = ip.split("::ffff:")[1];
  if (ip === "::1" || ip === "127.0.0.1") return null;
  return ip;
}

// Scan endpoint
app.get("/scan", async (req, res) => {
  if (!lookup) {
    return res.json({ result: "❌ Database Error" });
  }

  const ipParam = req.query.ip ? String(req.query.ip).trim() : null;
  const remoteHeader = req.headers["x-forwarded-for"] || null;
  const socketAddr = req.socket?.remoteAddress || null;

  let ipToUse = ipParam || normalizeIp(String(remoteHeader || socketAddr || ""));

  if (!ipToUse) {
    return res.json({ result: "📍 Localhost" });
  }

  // Lookup IP information
  let asnInfo = null;
  try {
    asnInfo = lookup.get(ipToUse);
  } catch (e) {
    asnInfo = null;
  }

  const isVPNDetected = isVPN(asnInfo);

  if (isVPNDetected) {
    res.json({ result: "🚫 VPN User" });
  } else {
    res.json({ result: "✅ Real User" });
  }
});

// Simple frontend
app.get("/", (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>VPN Check</title>
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
      background: #1a1a1a;
      color: white;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      text-align: center;
      padding: 40px;
    }
    .result {
      font-size: 48px;
      font-weight: bold;
      margin: 30px 0;
      padding: 20px;
      border-radius: 15px;
      background: #2a2a2a;
    }
    .btn {
      background: #007bff;
      color: white;
      border: none;
      padding: 15px 30px;
      border-radius: 10px;
      cursor: pointer;
      font-size: 18px;
      margin: 10px;
    }
    .samples {
      margin: 20px 0;
    }
    .sample-btn {
      background: #333;
      color: white;
      border: none;
      padding: 10px 15px;
      border-radius: 8px;
      cursor: pointer;
      margin: 5px;
      font-size: 14px;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔍 VPN Check</h1>
    
    <div id="result" class="result">Checking...</div>

    <button class="btn" onclick="scan()">Check Again</button>

    <div class="samples">
      <button class="sample-btn" onclick="testIP('8.8.8.8')">Test Real IP</button>
      <button class="sample-btn" onclick="testIP('185.159.157.1')">Test VPN IP</button>
    </div>
  </div>

  <script>
    async function scan(ip = null) {
      const resultEl = document.getElementById('result');
      resultEl.textContent = 'Checking...';
      
      try {
        const url = ip ? '/scan?ip=' + encodeURIComponent(ip) : '/scan';
        const response = await fetch(url);
        const data = await response.json();
        resultEl.textContent = data.result;
      } catch (error) {
        resultEl.textContent = '❌ Error';
      }
    }

    function testIP(ip) {
      scan(ip);
    }

    // Scan on page load
    scan();
  </script>
</body>
</html>`);
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running: http://localhost:${PORT}`);
});