# ZeroPhish Extension - Complete Fix Guide

## 🚨 The scan button is still not working because of CORS

Even though the gateway CORS is configured correctly, Chrome extensions require **special handling**.

## ✅ Complete Solution

The issue is that Chrome's CORS policy for extensions is very strict. Here's what you need to do:

### Step 1: Hard Reload the Extension

1. Go to `chrome://extensions/`
2. **Turn OFF** the ZeroPhish extension (toggle to gray)
3. Wait 2 seconds
4. **Turn ON** the extension (toggle to blue)
5. Click the **reload icon** 🔄
6. **Close all Gmail tabs**
7. **Open a fresh Gmail tab**

### Step 2: Clear Extension Cache

If Step 1 doesn't work, do this:

1. Go to `chrome://extensions/`
2. Click **"Remove"** on ZeroPhish extension
3. Click **"Load unpacked"** again
4. Select: `c:\Users\ASUS\Desktop\ZeroPhish\ZeroPhish1.0\Backend\extension`
5. Open Gmail in a **new tab**

### Step 3: Verify Services are Running

Make sure these are running in your terminals:

```powershell
# Terminal 1: Frontend (port 3000)
npm run dev

# Terminal 2: Tier 1 Backend (port 8000)  
uvicorn Backend.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 3: Gateway (port 8001)
cd Backend
$env:GATEWAY_PORT="8001"
python gateway.py
```

### Step 4: Test the Button

1. Open Gmail (mail.google.com)
2. Open **any email** (not just inbox)
3. Open the ZeroPhish extension side panel
4. Click **"INITIALIZE SCAN"**

## 🔍 Expected Behavior

You should see:
1. Status: "🔍 Reading Gmail content..."
2. Status: "⚡ Tier 1: Local analysis..."
3. Status: "🌐 Tier 2: Analyzing metadata..."
4. Status: "🤖 Tier 3: AI analyzing..."
5. A threat score (0-100)
6. Evidence list
7. Final verdict

## ❌ Still Not Working?

If you **still** see the CORS error after following ALL steps above:

### Option A: Check Browser Console
1. Press F12 in Chrome
2. Go to Console tab
3. Click "INITIALIZE SCAN"
4. Copy the **EXACT** error message
5. Share it with me

### Option B: Use the Web Dashboard Instead

The Chrome extension is optional. You can use the web dashboard:

1. Open http://localhost:3000 in your browser
2. Switch to "SAFE" or "THREAT" mode to see demo scans
3. The dashboard shows live scans from the extension

## 📝 Technical Details

The gateway is configured with:
- `allow_origins=["*"]` - Allows ALL origins including extensions
- `allow_methods=["GET", "POST", "DELETE", "OPTIONS"]` - All HTTP methods
- `allow_headers=["*"]` - All headers

This should work with Chrome extensions. If it doesn't, there may be a Chrome security policy blocking it.
