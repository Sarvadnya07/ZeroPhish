// content.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "EXTRACT_EMAIL") {
        // Targeted selectors for Gmail's 2026 DOM structure
        const bodyText = document.querySelector('.a3s.aiL')?.innerText || document.body.innerText;
        const senderEl = document.querySelector('.gD');
        const senderEmail = senderEl?.getAttribute('email') || "Unknown";
        const senderName =
            senderEl?.getAttribute('name') ||
            senderEl?.innerText?.trim() ||
            "Unknown";
        const subject = document.querySelector('.hP')?.innerText || "No Subject";
        const links = Array.from(document.querySelectorAll('a'))
            .map(a => ({
                href: a.href,
                text: (a.innerText || a.textContent || '').trim().substring(0, 120),
            }))
            .filter(l => typeof l.href === 'string' && /^https?:/i.test(l.href));

        sendResponse({ 
            body: bodyText.substring(0, 2500), // Tier 1 limit
            sender: senderEmail,
            senderEmail,
            senderName,
            subject, 
            links
        });
    } else if (request.action === "CREDENTIAL_LEAK_WARNING") {
        showInterstitialWarning("ZeroPhish Warning: You are typing a password into a suspicious or critical threat page!");
        sendResponse({ status: "warned" });
    }
    return true; // Keeps async channel open
});

// Behavioral Analysis: DOM mutation / Credential field monitoring
let passwordFieldFound = false;
const domObserver = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
        if (mutation.addedNodes.length) {
            const inputs = document.querySelectorAll('input[type="password"]');
            if (inputs.length > 0 && !passwordFieldFound) {
                passwordFieldFound = true;
                chrome.runtime.sendMessage({ action: "PASSWORD_FIELD_DETECTED" });
                
                inputs.forEach(input => {
                    input.addEventListener('keypress', (e) => {
                        chrome.runtime.sendMessage({ action: "PASSWORD_TYPED" });
                    }, { once: true });
                });
            }
        }
    }
});

domObserver.observe(document.body, { childList: true, subtree: true });

function showInterstitialWarning(message) {
    let overlay = document.getElementById('zerophish-warning-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'zerophish-warning-overlay';
        overlay.style.position = 'fixed';
        overlay.style.top = '0';
        overlay.style.left = '0';
        overlay.style.width = '100vw';
        overlay.style.height = '100vh';
        overlay.style.backgroundColor = 'rgba(239, 68, 68, 0.9)'; // Red with high opacity
        overlay.style.color = 'white';
        overlay.style.zIndex = '999999';
        overlay.style.display = 'flex';
        overlay.style.flexDirection = 'column';
        overlay.style.alignItems = 'center';
        overlay.style.justifyContent = 'center';
        overlay.style.fontFamily = 'sans-serif';
        overlay.style.backdropFilter = 'blur(10px)';

        const text = document.createElement('h1');
        text.innerText = "🚨 " + message;
        text.style.maxWidth = '80%';
        text.style.textAlign = 'center';
        text.style.marginBottom = '2rem';

        const btn = document.createElement('button');
        btn.innerText = "I understand, let me proceed";
        btn.style.padding = '12px 24px';
        btn.style.backgroundColor = 'white';
        btn.style.color = '#ef4444';
        btn.style.border = 'none';
        btn.style.borderRadius = '8px';
        btn.style.cursor = 'pointer';
        btn.style.fontWeight = 'bold';
        btn.onclick = () => overlay.remove();

        overlay.appendChild(text);
        overlay.appendChild(btn);
        document.body.appendChild(overlay);
    }
}
