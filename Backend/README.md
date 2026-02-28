# ZeroPhish Backend - Anti-Phishing Detection System

## 🛡️ Overview

ZeroPhish is a multi-tier phishing detection system that combines local heuristics, domain analysis, and threat intelligence to protect users from phishing attacks.

### Architecture

- **Tier 1 (Extension)**: Client-side heuristics + Local AI (BERT) for instant analysis
- **Tier 2 (Backend)**: WHOIS domain analysis + Speed Layer caching (Redis)
- **Tier 3 (AI)**: Advanced threat pattern analysis using local engine

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Redis (optional, for caching)
- Google Chrome browser (for extension)

### Installation

1. **Install Python Dependencies**

```bash
# Navigate to Backend directory
cd Backend

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

2. **Configure Environment Variables**

Create or update the `.env` file in the Backend directory:

```env
# Optional: Gemini API Key (for Tier 3 AI - currently not used in main backend)
GEMINI_API_KEY=your_actual_gemini_api_key_here
```

Create or update `tier_2/.env`:

```env
# Optional: Redis URL (defaults to localhost if not set)
REDIS_URL=redis://localhost:6379
```

3. **Optional: Install Redis**

Redis provides high-performance caching. If not installed, the system will work without it.

**Windows:**
- Download from: https://github.com/microsoftarchive/redis/releases
- Or use WSL: `sudo apt-get install redis-server`

**macOS:**
```bash
brew install redis
brew services start redis
```

**Linux:**
```bash
sudo apt-get install redis-server
sudo systemctl start redis
```

### Running the Backend

1. **Start the FastAPI Backend**

```bash
# From the Backend directory
cd tier_2
python main.py
```

The backend will start on `http://localhost:8000`

2. **Verify Backend is Running**

Open your browser and visit:
- Health Check: http://localhost:8000/health
- API Docs: http://localhost:8000/docs
- Cache Stats: http://localhost:8000/cache/stats

### Installing the Chrome Extension

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top-right)
3. Click "Load unpacked"
4. Select the `Backend/extension` folder
5. The ZeroPhish extension should now appear in your extensions

### Using ZeroPhish

1. Open Gmail (https://mail.google.com)
2. Open any email
3. Click the ZeroPhish extension icon to open the side panel
4. Click "INITIALIZE SCAN"
5. View the threat analysis results

## 📊 API Endpoints

### POST /scan
Analyze an email for phishing threats.

**Request:**
```json
{
  "sender": "sender@example.com",
  "body": "Email body text...",
  "links": ["https://example.com"]
}
```

**Response:**
```json
{
  "final_score": 75.5,
  "verdict": "SUSPICIOUS",
  "evidence": [
    "⚠️ Domain is relatively new (45 days).",
    "🔍 Threat detected: Urgency/Financial"
  ],
  "tier_details": {
    "domain_analysis": {
      "status": "SUSPICIOUS",
      "score": 60,
      "weight": 0.3
    },
    "threat_analysis": {
      "status": "CRITICAL",
      "score": 82,
      "weight": 0.7
    }
  },
  "threat_analysis": {
    "threat_level": 82,
    "category": "Urgency/Financial",
    "reasoning": "Detected 2 threat categories: Urgency, Financial",
    "flagged_phrases": ["urgent", "payment", "immediately"]
  },
  "cached": false
}
```

### GET /health
Health check endpoint.

### GET /cache/stats
Get Redis cache statistics.

### DELETE /cache/clear
Clear the Redis cache.

### GET /threat/patterns
Get all threat patterns used by the analyzer.

## 🔧 Testing

### Test Python Installation

```bash
python test_install.py
```

### Test Simple Python

```bash
python test_simple.py
```

### Manual API Testing

```bash
# Using curl
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "sender": "suspicious@newdomain.com",
    "body": "URGENT: Your account will be suspended unless you verify immediately!",
    "links": ["https://bit.ly/suspicious"]
  }'
```

## 🐛 Troubleshooting

### Backend won't start

1. **Check Python version**: `python --version` (should be 3.8+)
2. **Verify dependencies**: `pip install -r requirements.txt`
3. **Check port 8000**: Make sure nothing else is using port 8000

### Redis connection errors

- The system works without Redis (uses in-memory fallback)
- Check Redis is running: `redis-cli ping` (should return "PONG")
- Verify REDIS_URL in `tier_2/.env`

### Extension not working

1. **Refresh Gmail**: Hard refresh the Gmail page (Ctrl+Shift+R)
2. **Check backend**: Ensure backend is running on http://localhost:8000
3. **Check console**: Open Chrome DevTools (F12) and check for errors
4. **Reload extension**: Go to chrome://extensions and click reload

### WHOIS lookup fails

- Some domains may not have WHOIS data available
- The system will continue with a score of 0 (unknown)
- Check your internet connection

## 📁 Project Structure

```
Backend/
├── main.py                 # Tier 3 AI analysis (Gemini - optional)
├── requirements.txt        # Python dependencies
├── test_install.py        # Dependency test script
├── test_simple.py         # Simple Python test
├── .env                   # Environment variables
├── tier_2/                # Main backend application
│   ├── main.py           # FastAPI server with Tier 2 analysis
│   ├── speed_layer.py    # In-memory cache fallback
│   └── .env              # Redis configuration
└── extension/             # Chrome extension
    ├── manifest.json     # Extension configuration
    ├── background.js     # Service worker
    ├── content.js        # Gmail content extraction
    ├── sidepanel.html    # Extension UI
    ├── sidepanel.js      # UI logic + backend integration
    ├── style.css         # UI styling
    ├── tier1.js          # Local heuristic engine
    └── worker.js         # Web Worker for AI processing
```

## 🔒 Security Notes

- Never commit your `.env` file with real API keys
- The extension only accesses Gmail content when you click "INITIALIZE SCAN"
- All analysis happens locally or on your backend server
- No data is sent to third-party services (except optional Gemini API)

## 🚀 Performance

- **Tier 1 Analysis**: < 10ms (local heuristics)
- **Tier 2 Analysis**: 100-500ms (WHOIS lookup)
- **Cached Results**: < 5ms (Redis)
- **Total Analysis**: Typically < 1 second

## 📝 Configuration

### Adjusting Cache TTL

Edit `tier_2/main.py`:
```python
self.ttl = 300  # Change to desired seconds (default: 5 minutes)
```

### Customizing Threat Patterns

Edit the threat patterns in `tier_2/threat_patterns.json`:
- `URGENCY_PATTERNS`
- `FINANCIAL_PATTERNS`
- `CREDENTIAL_PATTERNS`
- `AUTHORITY_PATTERNS`
- `SCARE_TACTICS`
- `SUSPICIOUS_URLS`

## 🤝 Contributing

Feel free to submit issues and enhancement requests!

## 📄 License

This project is for educational and research purposes.

## 🔗 Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Chrome Extension Development](https://developer.chrome.com/docs/extensions/)
- [Redis Documentation](https://redis.io/documentation)
- [Google Gemini API](https://ai.google.dev/)
