# ZeroPhish - Quick Reference Guide

## 🚀 Quick Start Commands

### Start Backend Server
```powershell
# Automated (Recommended)
.\start_backend.ps1

# Manual
cd tier_2
python main.py
```

### Test Installation
```powershell
python test_install.py
```

---

## 🔗 Important URLs

| Service | URL |
|---------|-----|
| API Documentation | http://localhost:8000/docs |
| Health Check | http://localhost:8000/health |
| Cache Statistics | http://localhost:8000/cache/stats |
| Threat Patterns | http://localhost:8000/threat/patterns |

---

## 🧪 API Testing Examples

### Scan an Email
```powershell
# PowerShell
$body = @{
    sender = "suspicious@newdomain.com"
    body = "URGENT: Your account will be suspended!"
    links = @("https://bit.ly/suspicious")
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/scan" -Method Post -Body $body -ContentType "application/json"
```

```bash
# Bash/curl
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "sender": "suspicious@newdomain.com",
    "body": "URGENT: Your account will be suspended!",
    "links": ["https://bit.ly/suspicious"]
  }'
```

### Check Health
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/health"
```

### Clear Cache
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/cache/clear" -Method Delete
```

---

## 🛠️ Common Tasks

### Install Dependencies
```powershell
pip install -r requirements.txt
```

### Create Virtual Environment
```powershell
python -m venv venv
venv\Scripts\activate
```

### Update Dependencies
```powershell
pip install --upgrade -r requirements.txt
```

### Check Redis Connection
```powershell
redis-cli ping
# Should return: PONG
```

---

## 🐛 Troubleshooting

### Backend Won't Start

**Check Python version:**
```powershell
python --version
# Should be 3.8 or higher
```

**Check if port 8000 is in use:**
```powershell
netstat -ano | findstr :8000
```

**Kill process on port 8000:**
```powershell
# Find PID from above command, then:
taskkill /PID <PID> /F
```

### Extension Not Working

**Reload extension:**
1. Go to `chrome://extensions/`
2. Find ZeroPhish
3. Click reload button

**Check backend connection:**
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/health"
```

**Check browser console:**
1. Open extension side panel
2. Right-click → Inspect
3. Check Console tab for errors

### Redis Issues

**Check if Redis is running:**
```powershell
redis-cli ping
```

**Start Redis (Windows with WSL):**
```bash
sudo service redis-server start
```

**The system works without Redis** - it will use in-memory caching

---

## 📊 Threat Score Interpretation

| Score | Verdict | Meaning |
|-------|---------|---------|
| 0-29 | SAFE | Email appears legitimate |
| 30-69 | SUSPICIOUS | Exercise caution, verify sender |
| 70-100 | CRITICAL | High probability of phishing |

---

## 🔧 Configuration Files

### Backend/.env
```env
GEMINI_API_KEY=your_actual_gemini_api_key_here
```

### Backend/tier_2/.env
```env
REDIS_URL=redis://localhost:6379
```

---

## 📁 Key Files

| File | Purpose |
|------|---------|
| `tier_2/main.py` | Main FastAPI backend server |
| `extension/sidepanel.js` | Extension UI logic |
| `extension/content.js` | Gmail content extraction |
| `extension/worker.js` | AI model worker |
| `requirements.txt` | Python dependencies |

---

## 🎯 Extension Usage

1. **Open Gmail** → https://mail.google.com
2. **Open an email** → Click on any email
3. **Open ZeroPhish** → Click extension icon
4. **Scan** → Click "INITIALIZE SCAN"
5. **Review results** → Check threat score and evidence

---

## 💡 Tips

- **First scan may be slow** - AI model downloads on first use (~50MB)
- **Subsequent scans are fast** - Model is cached in browser
- **Backend caches results** - Identical emails return instantly
- **Works offline for Tier 1** - Local heuristics don't need backend
- **Redis is optional** - System works with in-memory cache

---

## 🔐 Security Best Practices

1. ✅ Never commit `.env` files to git
2. ✅ Use environment variables for secrets
3. ✅ Keep dependencies updated
4. ✅ Review extension permissions
5. ✅ Monitor backend logs for suspicious activity

---

## 📞 Support

### Check Logs

**Backend logs:**
- Displayed in terminal where backend is running

**Extension logs:**
- Right-click extension → Inspect → Console tab

### Common Error Messages

| Error | Solution |
|-------|----------|
| "Backend offline" | Start backend server |
| "Refresh Gmail and try again" | Hard refresh Gmail (Ctrl+Shift+R) |
| "Redis connection failed" | Install Redis or ignore (uses fallback) |
| "WHOIS lookup failed" | Normal for some domains, continues processing |

---

## 🚦 Status Indicators

### Extension Status Dot
- 🟢 **Green pulse** - System ready
- 🔴 **Red** - Error state

### Backend Health
```json
{
  "status": "healthy",
  "features": {
    "speed_layer": "Redis" or "None",
    "threat_analysis": "Local Engine",
    "domain_check": "WHOIS"
  }
}
```

---

**Quick Reference Version: 1.0**
**Last Updated: 2026-02-11**
