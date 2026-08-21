# How to Reload Chrome Extension - Step by Step

## ⚠️ CRITICAL: You MUST reload the extension for the changes to work!

The extension files were updated, but Chrome is still running the old cached version. Follow these exact steps:

### Step 1: Open Chrome Extensions Page
1. Open Chrome browser
2. Type in the address bar: `chrome://extensions/`
3. Press Enter

### Step 2: Find ZeroPhish Extension
Look for the extension named "ZeroPhish" or similar in the list

### Step 3: Reload the Extension
Click the **circular reload icon** (🔄) on the ZeroPhish extension card

**IMPORTANT**: Just disabling and re-enabling is NOT enough - you must click the reload button!

### Step 4: Verify the Extension is Loaded
- Make sure the extension toggle is ON (blue)
- Check that there are no error messages

### Step 5: Test the Scan Button
1. Open Gmail (mail.google.com)
2. Open any email
3. Open the ZeroPhish extension side panel
4. Click "INITIALIZE SCAN"

---

## 🔍 Troubleshooting

### If you see "Please open a Gmail message first"
- Make sure you're on `mail.google.com`
- Make sure you have an email open (not just the inbox)

### If you see "Could not read the email"
- Refresh the Gmail page
- Try opening a different email

### If you see "Gateway error: 404" or connection errors
- Make sure the gateway is running (check the terminal)
- The gateway should be on port 8001

### If nothing happens when you click the button
- Open Chrome DevTools (F12)
- Go to the Console tab
- Look for any error messages
- Share the error message with me

---

## ✅ How to Verify It's Working

When you click "INITIALIZE SCAN", you should see:
1. Status changes to "🔍 Reading Gmail content..."
2. Then "⚡ Tier 1: Local analysis..."
3. Then "🌐 Tier 2: Analyzing metadata..."
4. Finally "🤖 Tier 3: AI analyzing..."
5. A threat score appears (0-100)
6. Evidence and reasons are shown

---

## 🚨 Still Not Working?

If you've reloaded the extension and it's still not working, please tell me:
1. What error message do you see? (exact text)
2. Are you on Gmail with an email open?
3. What happens when you click the button? (does the status text change?)
4. Open DevTools Console (F12) - any red errors?
