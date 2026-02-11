/**
 * ZeroPhish Tier 1: Local Heuristic Engine
 * Executed in <10ms for instant feedback.
 */

const TIER1_ENGINE = {
    // 1. Semantic Triggers
    dangerKeywords: [
        /urgent/i, /action required/i, /verify/i, /suspend/i, 
        /password reset/i, /security alert/i, /unauthorized/i,
        /immediately/i, /account locked/i
    ],

    // 2. High-Trust Brands (Whitelist)
    trustedDomains: ['google.com', 'gmail.com', 'microsoft.com', 'paypal.com', 'apple.com'],

    // 3. Homograph Detection (Cyrillic/Greek look-alikes)
    homographRegex: /[^\u0000-\u007F]/,

    analyze: function(emailData) {
        let score = 0;
        let evidence = [];

        // Check A: Keyword Pressure
        const matchedKeywords = this.dangerKeywords.filter(regex => regex.test(emailData.body));
        if (matchedKeywords.length > 0) {
            score += 25;
            evidence.push(`🚨 High-pressure keywords: ${matchedKeywords.map(r => r.source).join(', ')}`);
        }

        // Check B: Link Deception
        emailData.links.forEach(link => {
            try {
                const url = new URL(link);
                const domain = url.hostname.toLowerCase().replace('www.', '');

                // Detect Link Mismatch (Text claims a brand, URL points elsewhere)
                this.trustedDomains.forEach(brand => {
                    if (emailData.body.toLowerCase().includes(brand) && !domain.includes(brand)) {
                        score += 35;
                        evidence.push(`⚠️ Brand Mismatch: Body mentions "${brand}" but links to "${domain}"`);
                    }
                });

                // Detect Homograph Attack (Look-alike characters)
                if (this.homographRegex.test(domain)) {
                    score += 40;
                    evidence.push(`🛑 Homograph Detected: "${domain}" contains non-Latin deceptive characters.`);
                }
            } catch (e) {
                // Invalid URL found
            }
        });

        return {
            t1_score: Math.min(score, 100),
            t1_evidence: evidence,
            t1_status: score > 0 ? "Suspicious" : "Clean"
        };
    }
};