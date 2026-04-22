# 📱 ZeroPhish Mobile Companion: Sentinel on the Go

ZeroPhish is now accessible as a high-performance Progressive Web App (PWA), allowing security leads and analysts to monitor and triage threats directly from their mobile devices without needing a native app store.

---

## 📥 Installation Guide

### **Android (Chrome)**
1.  **Navigate**: Open Google Chrome and go to your hosted ZeroPhish Dashboard URL.
2.  **Prompt**: You may see an "Add ZeroPhish to Home screen" banner at the bottom. Tap it.
3.  **Manual**: If no banner appears, tap the **three dots (⋮)** in the top right.
4.  **Install**: Select **"Install App"** (or "Add to Home screen").
5.  **Confirm**: Tap **Add**. The ZeroPhish icon will now appear on your home screen.

### **iOS / iPhone (Safari)**
1.  **Navigate**: Open Safari and go to your ZeroPhish Dashboard URL.
2.  **Share**: Tap the **Share icon** (square with an upward arrow) at the bottom center.
3.  **Add**: Scroll down and select **"Add to Home Screen"**.
4.  **Name**: Confirm the name is "ZeroPhish" and tap **Add** in the top right.
5.  **Launch**: Tap the new icon on your home screen to open the app in full-screen mode.

---

## 🛠️ How to Use the Mobile Companion

### 1. Real-Time Threat Monitoring
The mobile dashboard uses the same **WebSocket** infrastructure as the desktop version. You will see live "Pulse" animations whenever a new email is being scanned across your organization.

### 2. Interactive Triage
When a critical threat is detected, you can take immediate action from your phone:
- **Quarantine**: Tap the red **"Quarantine & Report"** button to isolate the email.
- **Resolve**: If you identify a false positive, tap **"Resolve Threat"**. This sends a signal back to the backend via WebSockets to clear the Redis cache and whitelist the sender.

### 3. Deep Forensics
Tap on any active scan to view the **Deep Forensics** drawer. This mobile-optimized view shows:
- **URL Inspector**: See where links actually point before opening them.
- **DOM Fingerprints**: View structural anomalies like hidden SVGs or CSS obfuscation.
- **Technical Logs**: Tap **"Explain Logic"** to see the raw ML and heuristic reasoning.

### 4. Offline Resilience
Thanks to the integrated **Service Worker**, the core UI and the most recent 10 forensic reports are cached on your device. You can review the last few critical incidents even if you lose connectivity (e.g., in an elevator or on a plane).

---

## 🛡️ Security Best Practices
- **Biometrics**: We recommend using your phone's built-in "App Lock" or Biometric security to protect the ZeroPhish app.
- **VPN**: Always ensure your mobile device is connected to your corporate VPN if your ZeroPhish Gateway is behind a firewall.
- **HTTPS**: PWA features require a valid SSL certificate to function correctly.

---

> [!TIP]
> To get the best experience, use the **Landscape Mode** on your phone to view more detailed forensic charts and comparison logs.
