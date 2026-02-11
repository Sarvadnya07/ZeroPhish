// content.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "EXTRACT_EMAIL") {
        // Targeted selectors for Gmail's 2026 DOM structure
        const bodyText = document.querySelector('.a3s.aiL')?.innerText || document.body.innerText;
        const sender = document.querySelector('.gD')?.getAttribute('email') || "Unknown";
        const subject = document.querySelector('.hP')?.innerText || "No Subject";
        const links = Array.from(document.querySelectorAll('a'))
            .map(a => ({
                href: a.href,
                text: (a.innerText || a.textContent || '').trim().substring(0, 120),
            }))
            .filter(l => typeof l.href === 'string' && /^https?:/i.test(l.href));

        sendResponse({ 
            body: bodyText.substring(0, 2500), // Tier 1 limit
            sender, 
            subject, 
            links
        });
    }
    return true; // Keeps async channel open
});
