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
    }
    return true; // Keeps async channel open
});
