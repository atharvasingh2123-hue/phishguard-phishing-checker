/* =====================================================================
   PhishGuard: script.js
   ---------------------------------------------------------------------
   Everything runs in the browser. Nothing is stored or sent anywhere,
   and this code NEVER opens, fetches or visits a pasted URL: it only
   reads the URL as plain text.

   HOW THIS FILE IS ORGANISED (read it top to bottom):
     PART 1  Lists & settings   – brands, risky endings (TLDs), keywords, shorteners…
     PART 2  URL_RULES          – rules for the URL checker  (EDIT HERE to add rules)
     PART 3  EMAIL_RULES        – rules for the email checker (EDIT HERE to add rules)
     PART 4  Examples           – sample phishing items for the demo buttons
     PART 5  Engine             – parses URLs/emails, runs the rules, calculates the score
     PART 6  User interface     – tabs, results, animations, dark mode

   THE BIG IDEA
     1. Each rule has a test (a small function) and a point value (weight).
     2. If the test finds something, the rule becomes a "red flag" and adds its points.
     3. Total points (max 100) = the risk percentage.
        0–24 = Safe-looking, 25–59 = Suspicious, 60+ = Likely phishing.

   SAFETY RULE FOR THE UI
     Anything the user pasted is only ever put on the page with .textContent
     (never .innerHTML), so it can't run as code (this prevents XSS).
   ===================================================================== */

"use strict"; // Makes JavaScript stricter, so silly typos are caught early.

/* =====================================================================
   PART 1: LISTS & SETTINGS (easy to edit!)
   ===================================================================== */

// Score limits for the risk levels.
const LEVELS = { suspicious: 25, phishing: 60 };

const LONG_URL_LENGTH = 90;   // URLs this long (or longer) are suspicious
const MAX_LINKS_CHECKED = 10; // how many links inside one email we analyse

/* ---------- Popular brands (used to find fake / lookalike websites) ----------
   name      – shown to the user
   keys      – the brand's name as it appears inside domains (lowercase)
   domains   – the REAL websites of the brand (a link to these is fine)
   aliases   – how the brand is written in an email's display name or text (lowercase) */
const BRANDS = [
  { name: "SBI (State Bank of India)", keys: ["sbi", "onlinesbi", "yonosbi"], domains: ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbi.bank.in"], aliases: ["sbi", "state bank"] },
  { name: "HDFC Bank", keys: ["hdfc", "hdfcbank"], domains: ["hdfcbank.com", "hdfc.com"], aliases: ["hdfc"] },
  { name: "ICICI Bank", keys: ["icici", "icicibank"], domains: ["icicibank.com", "icicidirect.com", "icicilombard.com"], aliases: ["icici"] },
  { name: "Axis Bank", keys: ["axisbank"], domains: ["axisbank.com", "axis.bank.in"], aliases: ["axis bank"] },
  { name: "Kotak Mahindra Bank", keys: ["kotak", "kotakbank"], domains: ["kotak.com"], aliases: ["kotak"] },
  { name: "Punjab National Bank", keys: ["pnb", "pnbindia"], domains: ["pnbindia.in", "netpnb.com"], aliases: ["pnb", "punjab national bank"] },
  { name: "Bank of Baroda", keys: ["bankofbaroda"], domains: ["bankofbaroda.in", "bankofbaroda.com"], aliases: ["bank of baroda"] },
  { name: "Paytm", keys: ["paytm"], domains: ["paytm.com", "paytmbank.com", "paytm.in"], aliases: ["paytm"] },
  { name: "PhonePe", keys: ["phonepe"], domains: ["phonepe.com"], aliases: ["phonepe", "phone pe"] },
  { name: "Google / Google Pay", keys: ["google", "gpay", "googlepay"], domains: ["google.com", "google.co.in", "googleapis.com", "gstatic.com", "googleusercontent.com", "gmail.com", "youtube.com"], aliases: ["google", "gpay", "google pay"] },
  { name: "Amazon", keys: ["amazon"], domains: ["amazon.in", "amazon.com", "amazon.co.uk", "amazonaws.com"], aliases: ["amazon"] },
  { name: "Flipkart", keys: ["flipkart"], domains: ["flipkart.com", "flipkart.net"], aliases: ["flipkart"] },
  { name: "PayPal", keys: ["paypal"], domains: ["paypal.com", "paypal.me"], aliases: ["paypal"] },
  { name: "Microsoft", keys: ["microsoft", "office365"], domains: ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "office365.com"], aliases: ["microsoft", "outlook", "office 365"] },
  { name: "Apple", keys: ["apple", "icloud"], domains: ["apple.com", "icloud.com"], aliases: ["apple", "icloud"] },
  { name: "Facebook / Instagram / WhatsApp", keys: ["facebook", "instagram", "whatsapp"], domains: ["facebook.com", "fb.com", "instagram.com", "whatsapp.com", "meta.com"], aliases: ["facebook", "instagram", "whatsapp"] },
  { name: "Netflix", keys: ["netflix"], domains: ["netflix.com"], aliases: ["netflix"] },
  { name: "Income Tax Department", keys: ["incometax", "incometaxindia"], domains: ["incometax.gov.in", "incometaxindia.gov.in"], aliases: ["income tax", "incometax", "cbdt"] },
  { name: "Aadhaar / UIDAI", keys: ["aadhaar", "aadhar", "uidai"], domains: ["uidai.gov.in"], aliases: ["aadhaar", "aadhar", "uidai"] },
  { name: "India Post", keys: ["indiapost", "speedpost"], domains: ["indiapost.gov.in"], aliases: ["india post", "indiapost", "speed post"] },
  { name: "IRCTC", keys: ["irctc"], domains: ["irctc.co.in"], aliases: ["irctc"] },
  { name: "EPFO (Provident Fund)", keys: ["epfo", "epfindia"], domains: ["epfindia.gov.in", "epfo.gov.in"], aliases: ["epfo", "provident fund"] },
  { name: "NPCI / BHIM", keys: ["npci", "bhim"], domains: ["npci.org.in"], aliases: ["npci", "bhim"] },
  { name: "Jio", keys: ["jio"], domains: ["jio.com", "ril.com"], aliases: ["jio"] },
  { name: "Airtel", keys: ["airtel"], domains: ["airtel.in", "airtel.com"], aliases: ["airtel"] },
  { name: "DHL", keys: ["dhl"], domains: ["dhl.com"], aliases: ["dhl"] },
  { name: "FedEx", keys: ["fedex"], domains: ["fedex.com"], aliases: ["fedex"] },
  { name: "Blue Dart", keys: ["bluedart"], domains: ["bluedart.com"], aliases: ["blue dart", "bluedart"] },
  { name: "Delhivery", keys: ["delhivery"], domains: ["delhivery.com"], aliases: ["delhivery"] }
];

// Link shorteners hide the real destination.
const SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "ow.ly",
  "tiny.cc", "s.id", "t.ly", "rebrand.ly", "v.gd", "buff.ly", "lnkd.in", "bl.ink", "shrtco.de", "qr.ae"
];

// Website endings (TLDs) that are cheap and very often used by phishing sites.
const SUSPICIOUS_TLDS = [
  "xyz", "top", "tk", "click", "work", "ml", "ga", "cf", "gq", "icu", "vip", "live", "buzz", "cyou",
  "sbs", "cfd", "rest", "site", "online", "link", "support", "help", "monster", "fun", "zip", "mov"
];

// Words in the path/query that phishers like to use (e.g. /login/verify-kyc).
const PATH_KEYWORDS = [
  "login", "signin", "log-in", "verify", "verification", "update", "secure", "security", "kyc", "otp",
  "reward", "refund", "claim", "confirm", "password", "suspended", "unlock", "bonus", "wallet", "validate"
];

// File types that can install malware.
const DOWNLOAD_EXTENSIONS = ["apk", "exe", "zip", "msi", "scr", "bat", "rar", "jar"];

// "Two-part" endings, so that sbi.co.in is split as name "sbi" + ending "co.in".
const MULTI_PART_SUFFIXES = [
  "co.in", "gov.in", "nic.in", "ac.in", "org.in", "net.in", "res.in", "firm.in", "gen.in", "ind.in",
  "co.uk", "org.uk", "com.au", "co.nz", "com.br", "co.za", "com.sg", "com.my", "co.jp"
];

// Extra words scammers glue to a short brand name (e.g. "sbikyc", "updatesbi").
const SCAM_WORDS = [
  "kyc", "update", "verify", "login", "secure", "reward", "rewards", "bank", "online", "card", "care",
  "support", "help", "refund", "claim", "offer", "bonus", "gift", "pay", "netbanking", "account",
  "alert", "customer", "service"
];

// Brand-like words that are NOT typos of a brand (stops false alarms, e.g. "apply" vs "apple").
const NOT_TYPOS = ["apply", "apples", "pineapple", "maple", "ample"];

// Free email providers (a real company or bank doesn't send official mail from these).
const FREE_EMAIL_DOMAINS = [
  "gmail.com", "yahoo.com", "yahoo.in", "outlook.com", "hotmail.com", "live.com", "rediffmail.com",
  "protonmail.com", "proton.me", "aol.com", "icloud.com", "mail.com", "zoho.com", "gmx.com"
];

// Words that make a display name sound like an official organisation.
const ORG_WORDS = /\b(?:bank|support|customer|care|helpdesk|help desk|department|dept|security|alert|alerts|service|services|official|admin|team|refund|kyc|billing|accounts?)\b/i;

// Typical spelling mistakes seen in phishing emails.
const COMMON_MISSPELLINGS = [
  "recieve", "acount", "accout", "verfiy", "verifiy", "verifcation", "securty", "secuirty", "informations",
  "immediatly", "imediately", "pasword", "passwrod", "confirmaton", "suspened", "suspnded", "dissabled",
  "temporarly", "custmer", "costumer", "detials", "transection", "transcation", "attension", "kindy"
];

// File types in an email that are dangerous to open.
const DANGEROUS_ATTACHMENT_EXTENSIONS = [
  "zip", "exe", "html", "htm", "apk", "scr", "js", "vbs", "jar", "iso", "rar", "msi", "bat", "docm", "xlsm", "pptm", "7z"
];

// Words for private details. Used by the "asks for secrets" rule in EMAIL_RULES.
const SENSITIVE_ITEMS =
  "otp|one[- ]time[- ]password|upi[- ]?pin|atm[- ]?pin|pin|cvv|cvc|aadhaar|aadhar|pan(?:[- ]card)?|card[- ]number|" +
  "card[- ]details|debit[- ]card|credit[- ]card|password|passcode|net[- ]?banking|expiry[- ]date|account[- ]number|" +
  "bank[- ]details|login[- ]credentials|credentials";

/* =====================================================================
   PART 2: URL RULES
   ---------------------------------------------------------------------
   Each rule is an object:
     id        – short unique name
     title     – heading shown to the user
     icon      – an emoji
     weight    – points added to the risk score
     why       – a plain-English explanation of why it is dangerous
     tip       – (optional) safety tip
     highlight – which part(s) of the URL to highlight when this rule fires:
                 "protocol", "userinfo", "subdomain", "domain", "port", "path", "query"
     test(u)   – a function that gets the parsed URL "u" (see parseInputUrl) and returns:
                   false                    → rule did NOT trigger
                   true                     → triggered
                   { found:[…text…], weight?:n, highlight?:[…] } → triggered, with details
   Each rule counts ONCE. TO ADD A NEW RULE: copy one, change it, save. That's it!
   ===================================================================== */
const URL_RULES = [
  {
    id: "http", title: "Not secure: uses HTTP instead of HTTPS", icon: "🔓", weight: 15, highlight: ["protocol"],
    why: "http:// links are not encrypted, so anything you type (like a password) can be read by others. Real banks and shops always use https://.",
    test: (u) => u.hasScheme && u.protocol === "http:"
  },
  {
    id: "ip-host", title: "Uses an IP address instead of a website name", icon: "🔢", weight: 35, highlight: ["domain"],
    why: "Real companies use names like sbi.co.in, not numbers like 192.168.1.5. Phishers often host fake pages on raw IP addresses to avoid having a name.",
    test: (u) => u.hostIsIp && { found: [u.host] }
  },
  {
    id: "shortener", title: "Shortened link (hides the real website)", icon: "✂️", weight: 30, highlight: ["domain"],
    why: "Short links like bit.ly or tinyurl hide where you will really land. Banks and the tax department don't send important links this way.",
    tip: "Do not open short links from messages you didn't expect.",
    test: (u) => (SHORTENERS.includes(u.host) || SHORTENERS.includes(u.domain)) && { found: [u.host] }
  },
  {
    id: "many-subdomains", title: "Too many subdomains", icon: "🪜", weight: 20, highlight: ["subdomain"],
    why: "Phishers stack words in front of a domain (like login.secure.sbi.verify.example.com) to make it look official. Only the part right before the ending counts (here: example.com).",
    test: (u) => !u.hostIsIp && u.subLabels.length >= 3 && { found: [u.subdomain] }
  },
  {
    id: "long-url", title: "Very long URL", icon: "📏", weight: 8, highlight: ["path", "query"],
    why: "Very long links are often used to bury the suspicious part, or to carry tracking codes that identify you.",
    test: (u) => u.raw.length >= LONG_URL_LENGTH && { found: [u.raw.length + " characters"] }
  },
  {
    id: "hyphens-digits", title: "Odd domain: many hyphens or digits", icon: "➖", weight: 12, highlight: ["domain"],
    why: "Real brands have short, clean names. Names like “sbi-kyc-update-2024” or “x9k2m7pq” are typical of throw-away phishing sites.",
    test: (u) => {
      if (u.hostIsIp || isOfficialHost(u.host)) return false;
      const hyphens = (u.name.match(/-/g) || []).length;
      const digits = (u.name.match(/\d/g) || []).length;
      const hostHyphens = (u.host.match(/-/g) || []).length;
      return (hyphens >= 2 || digits >= 3 || hostHyphens >= 3 || u.name.length >= 25) && { found: [u.name] };
    }
  },
  {
    id: "at-symbol", title: "Contains an @ symbol", icon: "📧", weight: 30, highlight: ["userinfo"],
    why: "In a web address, everything BEFORE an @ is ignored by the browser. A link like https://sbi.co.in@evil.xyz really goes to evil.xyz. It is a trick to make a fake link look real.",
    test: (u) => u.raw.includes("@") && (u.username
      ? { found: [u.username + "@"], weight: 30, highlight: ["userinfo"] }
      : { found: ["@"], weight: 12, highlight: ["path", "query"] })
  },
  {
    id: "suspicious-tld", title: "Risky website ending", icon: "🏷️", weight: 20, highlight: ["domain"],
    why: "Endings like .xyz, .top, .tk, .click or .work are very cheap (some are free), so criminals use them a lot. Banks and government sites use .com, .in, .co.in or .gov.in.",
    test: (u) => !u.hostIsIp && SUSPICIOUS_TLDS.includes(u.tldLast) && { found: ["." + u.tldLast] }
  },
  {
    id: "brand-in-domain", title: "Brand name inside a website that isn't theirs", icon: "🎣", weight: 35, highlight: ["domain"],
    why: "The address uses a famous name (like “sbi” or “paytm”) but it is NOT the real website. Anyone can register sbi-kyc-update.xyz. This is the most common phishing trick.",
    tip: "Go to the real website by typing its address yourself.",
    test: (u) => {
      if (u.hostIsIp) return false;
      const found = [];
      const where = new Set();
      for (const brand of BRANDS) {
        if (isOfficialFor(u.host, brand)) continue;
        for (const key of brand.keys) {
          if (!hostHasKey(u.host, key)) continue;
          found.push(`“${key}” (${brand.name})`);
          if (u.subdomain.includes(key)) where.add("subdomain");
          if (u.domain.includes(key)) where.add("domain");
        }
      }
      return found.length > 0 && { found: [...new Set(found)], highlight: where.size ? [...where] : ["domain"] };
    }
  },
  {
    id: "typosquat", title: "Lookalike (typo) of a famous brand", icon: "🔡", weight: 40, highlight: ["domain"],
    why: "The name is almost the same as a real brand but with a small change (like paypa1, amaz0n or hdfcbamk). Your eyes read it as the real one, so it is called “typosquatting”.",
    tip: "Read the website name slowly, letter by letter.",
    test: (u) => {
      if (u.hostIsIp || isOfficialHost(u.host)) return false;
      const found = findTyposquat(u);
      return found.length > 0 && { found };
    }
  },
  {
    id: "brand-in-path", title: "Brand name only in the page address", icon: "🗂️", weight: 15, highlight: ["path", "query"],
    why: "The brand name appears after the website name (like evil.com/sbi/login). Anyone can name a page anything, so this proves nothing. It is used to look convincing.",
    test: (u) => {
      if (u.hostIsIp) return false;
      const tokens = u.pathQuery.split(/[^a-z0-9]+/).filter(Boolean);
      const found = [];
      for (const brand of BRANDS) {
        if (isOfficialFor(u.host, brand)) continue;
        for (const key of brand.keys) {
          const hit = key.length >= 5 ? tokens.some((t) => t.includes(key)) : tokens.includes(key);
          if (hit) found.push(`“${key}” (${brand.name})`);
        }
      }
      return found.length > 0 && { found: [...new Set(found)] };
    }
  },
  {
    id: "path-keywords", title: "Suspicious words in the link (login, verify, kyc…)", icon: "🗝️", weight: 10, highlight: ["path", "query"],
    why: "Words like login, verify, update, kyc, otp or reward are used to push you into entering details. They are normal on real sites too, but are a warning sign when combined with other flags.",
    test: (u) => {
      const found = PATH_KEYWORDS.filter((k) => u.pathQuery.includes(k));
      return found.length > 0 && { found };
    }
  },
  {
    id: "punycode", title: "Punycode / look-alike international characters", icon: "🈲", weight: 30, highlight: ["domain"],
    why: "Domains starting with “xn--” use special international letters that can look identical to normal ones (for example a Cyrillic “а” instead of an English “a”). Phishers use them to copy real names.",
    test: (u) => {
      const found = u.labels.filter((l) => l.startsWith("xn--"));
      return found.length > 0 && { found };
    }
  },
  {
    id: "download", title: "Link downloads a risky file", icon: "💾", weight: 30, highlight: ["path"],
    why: "Links ending in .apk, .exe or .zip download programs or archives that can hide malware. A bank or tax office will never ask you to install something from a link.",
    tip: "Never install apps or run files that arrive through a link. Only use the official app store.",
    test: (u) => {
      const m = u.pathname.toLowerCase().match(new RegExp("([^/]+\\.(?:" + DOWNLOAD_EXTENSIONS.join("|") + "))$"));
      return m && { found: [m[1]] };
    }
  },
  {
    id: "port", title: "Unusual port number", icon: "🚪", weight: 8, highlight: ["port"],
    why: "Normal websites don't show a port number. An odd one like :8080 often means a temporary server set up by a criminal.",
    test: (u) => u.port !== "" && !["80", "443"].includes(u.port) && { found: [":" + u.port] }
  }
];

/* =====================================================================
   PART 3: EMAIL RULES
   ---------------------------------------------------------------------
   Same idea as URL_RULES, but the test function gets the parsed email "e"
   (see buildEmailContext). A rule can also have:
     patterns       – a list of regular expressions run on the subject + body text
     skipIfNegated  – ignore matches like "do NOT share your OTP"
   ===================================================================== */
const EMAIL_RULES = [
  {
    id: "sender-mismatch", title: "Sender doesn't match who they claim to be", icon: "🎭", weight: 35,
    why: "Anyone can type “SBI Bank” as the display name. The real sender is the address after the @. A bank writes from its own domain, not from gmail.com or a random website.",
    tip: "Check the address after the @ in the sender line, not just the name.",
    test: (e) => {
      const m = findSenderMismatch(e);
      return m && { found: [m] };
    }
  },
  {
    id: "sender-domain-fake", title: "Sender's email domain looks fake", icon: "🕸️", weight: 25,
    why: "The domain the email comes from has the same tricks as a phishing website: a brand name in a non-official domain, a typo of a brand, a risky ending, or look-alike characters.",
    test: (e) => {
      if (!e.domain) return false;
      const u = parseInputUrl("https://" + e.domain);
      if (u.error) return false;
      const checks = URL_RULES.filter((r) => ["brand-in-domain", "typosquat", "suspicious-tld", "punycode", "hyphens-digits"].includes(r.id));
      const result = runRules(checks, u);
      return result.flags.length > 0 && { found: [e.domain, ...result.flags.map((f) => f.title)] };
    }
  },
  {
    id: "free-mail-org", title: "Official-sounding message from a free email service", icon: "📮", weight: 12,
    why: "Companies, banks and government offices use their own email domain. A free address (like gmail.com) for an “official” message is a warning sign.",
    test: (e) => {
      if (!FREE_EMAIL_DOMAINS.includes(e.domain) || findSenderMismatch(e)) return false;
      const claimsOrg = ORG_WORDS.test(e.displayName) || brandsInText((e.subject + " " + e.bodyText).slice(0, 600)).length > 0;
      return claimsOrg && { found: [e.domain] };
    }
  },
  {
    id: "urgency", title: "Urgency or threats", icon: "⏰", weight: 15,
    why: "Phishers rush and scare you (“account suspended”, “within 24 hours”, “legal action”) so you click before you think. Real organisations give you proper time and don't threaten by email.",
    tip: "Pause. Contact the organisation yourself on its official number or website.",
    patterns: [
      /\b(?:immediately|urgent(?:ly)?|asap|act now|right away|as soon as possible|final (?:notice|warning|reminder)|last (?:chance|warning)|expires? (?:today|soon|in \d+)|limited time)\b/i,
      /\bwithin\s+(?:the\s+next\s+)?\d+\s*(?:hours?|hrs?|minutes?|mins?|days?)\b/i,
      /\b(?:account|card|access|service|kyc|sim|pan|login)\b[^.!?\n]{0,30}\b(?:will be|has been|have been|is)\s+(?:suspended|blocked|closed|terminated|deactivated|disabled|locked|limited|restricted|frozen)\b/i,
      /\blegal action\b|\b(?:arrest|penalt(?:y|ies)|prosecution)\b|\bfailure to (?:comply|respond|verify|update)\b/i
    ]
  },
  {
    id: "sensitive", title: "Asks for passwords, OTP, PIN or card details", icon: "🔑", weight: 35,
    why: "No bank, tax office or company will ever ask for your password, OTP, PIN, CVV, Aadhaar or PAN by email. Whoever gets them can empty your account.",
    tip: "If you already shared such details, call your bank right now to block the card/account, then call 1930.",
    skipIfNegated: true, // “Never share your OTP” is a warning, not a request
    patterns: [
      new RegExp("\\b(?:share|send|give|tell|provide|enter|submit|confirm|reconfirm|verify|reply(?: with)?|type|fill|update|disclose)\\b[^.!?\\n]{0,40}?\\b(?:" + SENSITIVE_ITEMS + ")\\b", "i"),
      new RegExp("\\b(?:" + SENSITIVE_ITEMS + ")\\b\\s*(?:is\\s+|are\\s+)?(?:required|needed|mandatory|expired)", "i"),
      new RegExp("\\b(?:with|using)\\s+your\\s+(?:" + SENSITIVE_ITEMS + ")\\b", "i")
    ]
  },
  {
    id: "greeting", title: "Generic greeting (“Dear Customer”)", icon: "👤", weight: 10,
    why: "Mass phishing emails don't know your name. A real bank or company that has your account usually greets you by name.",
    patterns: [
      /\bdear\s+(?:valued\s+)?(?:customer|user|sir|madam|sir\/madam|account\s*holder|bank customer|client|member|taxpayer|subscriber|friend|winner)\b/i,
      /\bhello\s+(?:customer|user|sir|madam)\b/i
    ]
  },
  {
    id: "links", title: "Suspicious link inside the email", icon: "🔗", weight: 30,
    why: "Every link in the email was checked with the URL rules. At least one of them has serious warning signs (see the link list above and the details for each link).",
    tip: "Don't click any link in the email. Type the real website address yourself.",
    test: (e) => {
      const bad = e.linkResults.filter((l) => l.score >= 20);
      if (bad.length === 0) return false;
      const worst = Math.max(...bad.map((l) => l.score));
      // Points depend on how bad the worst link is (max 45).
      return { weight: Math.min(45, Math.round(worst * 0.6)), found: bad.map((l) => l.url + " → " + l.score + "%") };
    }
  },
  {
    id: "link-mismatch", title: "Link text doesn't match where it really goes", icon: "🎯", weight: 35,
    why: "The email shows one website name but the link secretly goes to another. For example the text says www.indiapost.gov.in, but clicking leads to indiapost-redelivery.top. This is a classic phishing trick.",
    tip: "Never trust the text of a link. On a computer you can hover over it to see the real address.",
    test: (e) => {
      const found = [];
      for (const a of e.anchors) {
        const hrefHost = hostOfUrl(a.href);
        if (!hrefHost || !a.text) continue;
        const shown = a.text.match(/(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[\/\s:?#]|$)/i);
        if (shown) {
          const shownHost = shown[1].toLowerCase().replace(/^www\./, "");
          if (splitHost(shownHost).domain !== splitHost(hrefHost).domain) found.push(`shows “${shownHost}” but goes to “${hrefHost}”`);
        } else {
          const brand = brandsInText(a.text)[0];
          if (brand && !isOfficialFor(hrefHost, brand)) found.push(`says “${a.text.slice(0, 40)}” but goes to “${hrefHost}”`);
        }
      }
      return found.length > 0 && { found };
    }
  },
  {
    id: "attachment", title: "Risky attachment or “enable macros” request", icon: "📎", weight: 30,
    why: "Files like .zip, .exe, .html, .apk or macro-enabled documents (.docm, .xlsm) can install malware or open fake login pages. Phishers send them as “invoices”, “refund forms” or “statements”.",
    tip: "Never open an unexpected attachment, even if it looks like a PDF or a form.",
    test: (e) => {
      const re = new RegExp("[\\w\\-.()]+\\.(?:" + DANGEROUS_ATTACHMENT_EXTENSIONS.join("|") + ")\\b", "gi");
      const files = e.textNoUrls.match(re) || [];
      const macro = e.textNoUrls.match(/\benable\s+(?:macros?|content|editing)\b|\bmacro[- ]enabled\b/gi) || [];
      const found = [...new Set([...files, ...macro])];
      return found.length > 0 && { found };
    }
  },
  {
    id: "prize-refund", title: "Prize, refund or tax-refund claim", icon: "🎁", weight: 25,
    why: "“You are eligible for a refund” or “you have won” is bait. You won't get free money by email, and the “claim” page will ask for your bank details.",
    tip: "Check refunds only by logging in to the official website you typed yourself.",
    patterns: [
      /\b(?:tax\s+refund|income\s+tax\s+refund|refund\s+(?:of|amount|is|has|pending|approved|initiated)|refund(?:ed)?\s+(?:rs\.?|₹|inr)|you(?:['’]ve|\s+have)\s+(?:been\s+)?(?:won|selected)|you\s+are\s+(?:eligible|entitled)|lottery|prize|reward\s+points?|cash\s?back|claim\s+your|unclaimed|free\s+gift|gift\s+(?:card|voucher)|congratulations?)/i
    ]
  },
  {
    id: "spelling", title: "Spelling or grammar mistakes", icon: "✍️", weight: 8,
    why: "Official emails are proofread. Typos and odd wording (“kindly do the needful”, “your account have been blocked”) are common in phishing.",
    patterns: [
      new RegExp("\\b(?:" + COMMON_MISSPELLINGS.join("|") + ")\\b", "i"),
      /\bkindly\b/i,
      /\bdo the needful\b/i,
      /\b(?:have|has)\s+been\s+(?:block|suspend|expire|lock|deactivate)\b/i,
      /\b(?:plz|pls|u r)\b/i
    ]
  },
  {
    id: "caps", title: "Too many CAPITAL LETTERS", icon: "🔠", weight: 6,
    why: "Shouting in capital letters is used to create panic.",
    test: (e) => {
      const letters = e.textNoUrls.match(/[A-Za-z]/g) || [];
      const upper = e.textNoUrls.match(/[A-Z]/g) || [];
      if (letters.length < 30 || upper.length / letters.length < 0.3) return false;
      return { found: [...new Set(e.textNoUrls.match(/\b[A-Z]{4,}\b/g) || [])].slice(0, 5) };
    }
  },
  {
    id: "exclaim", title: "Too many exclamation marks!!!", icon: "❗", weight: 6,
    why: "Real organisations write calmly. Lots of exclamation marks create fake excitement or fear.",
    test: (e) => ((e.textNoUrls.match(/!/g) || []).length >= 3) && { found: ["!!!"] }
  }
];

/* =====================================================================
   PART 4: EXAMPLES (all fake, for demo purposes)
   ===================================================================== */
const EXAMPLES = [
  { label: "🏦 Fake SBI KYC URL", mode: "url", url: "http://sbi-kyc-update.xyz/login/verify?acc=88231" },
  { label: "🛒 Typosquatted Amazon link", mode: "url", url: "https://www.amaz0n.in/account/verify" },
  {
    label: "🧾 Fake Income Tax refund email", mode: "email",
    from: "Income Tax Department <refund@incometax-india-support.com>",
    subject: "URGENT: Income Tax Refund of Rs 24,580 approved",
    body:
      "Dear Taxpayer,\n\n" +
      "After the final calculation of your annual income, you are eligible for a tax refund of Rs 24,580. " +
      "To receive the refund within 24 hours, please verify your PAN card number, Aadhaar and net banking password at the link below:\n\n" +
      "https://incometax-refund.click/claim\n\n" +
      "Also open the attached form TaxRefund_Form.zip and fill it in. Failure to do so will lead to legal action.\n\n" +
      "Income Tax Department"
  },
  {
    label: "📦 Fake delivery email (HTML)", mode: "email",
    from: "India Post Delivery <delivery.update@indiapost-tracking.top>",
    subject: "Your parcel is on hold: action required",
    body:
      "<p>Dear Customer,</p>" +
      "<p>Your parcel could not be delivered because the address is incomplete. Pay a small redelivery fee of Rs 25 within 12 hours or the parcel will be returned.</p>" +
      "<p><a href=\"http://indiapost-redelivery.top/track?id=IN8837\">https://www.indiapost.gov.in/track</a></p>" +
      "<p>India Post Customer Care</p>"
  },
  { label: "✂️ Shortened link", mode: "url", url: "https://bit.ly/3xK9pQa" },
  { label: "✅ Safe-looking URL", mode: "url", url: "https://www.sbi.co.in/" }
];

/* =====================================================================
   PART 5: THE ENGINE (parses text and runs the rules, no HTML in here)
   ===================================================================== */

/* ---------- Small helpers ---------- */

// Does the host belong to this brand's REAL websites?
function isOfficialFor(host, brand) {
  if (host.endsWith(".gov.in") || host.endsWith(".nic.in")) return true; // Indian government sites
  return brand.domains.some((d) => host === d || host.endsWith("." + d));
}

// Is the host the real site of ANY brand in our list (or an Indian government site)?
function isOfficialHost(host) {
  return host.endsWith(".gov.in") || host.endsWith(".nic.in") || BRANDS.some((b) => isOfficialFor(host, b));
}

// Does the host contain this brand key? (short keys need a stricter check)
function hostHasKey(host, key) {
  // "sbi-kyc-update.xyz" → ["sbi","kyc","update","xyz"]  (ordinary words like "pineapple" are ignored)
  const tokens = host.split(/[.\-]/).filter((t) => !NOT_TYPOS.includes(t));
  if (key.length >= 5) return tokens.some((t) => t.includes(key));
  return tokens.some((t) => t === key || SCAM_WORDS.some((w) => t === key + w || t === w + key));
}

// Which brands are mentioned in some text (by their aliases)?
function brandsInText(text) {
  const lower = " " + text.toLowerCase().replace(/[^a-z0-9]+/g, " ") + " ";
  return BRANDS.filter((b) => b.aliases.some((a) => lower.includes(" " + a + " ")));
}

/* ---------- Levenshtein distance ----------
   The number of single-letter changes (insert / delete / replace) needed to turn
   word A into word B. "amaz0n" → "amazon" = 1 change, so they are very similar. */
function levenshtein(a, b) {
  const rows = a.length + 1, cols = b.length + 1;
  const d = Array.from({ length: rows }, (_, i) => [i, ...new Array(cols - 1).fill(0)]);
  for (let j = 0; j < cols; j++) d[0][j] = j;
  for (let i = 1; i < rows; i++) {
    for (let j = 1; j < cols; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
    }
  }
  return d[a.length][b.length];
}

// Undo common look-alike tricks: 0→o, 1→l / i, 5→s, 3→e, rn→m, vv→w
function lookalikeForms(word) {
  const base = word.replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o").replace(/5/g, "s").replace(/3/g, "e");
  return [base.replace(/1/g, "l"), base.replace(/1/g, "i")];
}

// Find names in the host that are "almost" a famous brand (but not exactly it).
function findTyposquat(u) {
  const candidates = [u.name, ...u.name.split("-")].filter((c, i, arr) => c.length >= 4 && arr.indexOf(c) === i);
  const found = [];
  for (const brand of BRANDS) {
    for (const key of brand.keys.filter((k) => k.length >= 5)) {
      for (const cand of candidates) {
        if (cand === key || NOT_TYPOS.includes(cand)) continue;
        const maxEdits = key.length >= 8 ? 2 : 1;
        const close = levenshtein(cand, key) <= maxEdits;
        const tricky = lookalikeForms(cand).includes(key);
        if (close || tricky) found.push(`“${cand}” looks like “${key}” (${brand.name})`);
      }
    }
  }
  return [...new Set(found)];
}

/* ---------- Split a host name into parts ----------
   "login.secure.sbi-kyc.co.in" → subdomain "login.secure", name "sbi-kyc", ending "co.in",
   registrable domain "sbi-kyc.co.in" (the part someone actually bought). */
function splitHost(host) {
  const labels = host.split(".");
  let suffixLen = 1;
  if (labels.length > 2 && MULTI_PART_SUFFIXES.includes(labels.slice(-2).join("."))) suffixLen = 2;
  if (labels.length <= suffixLen) {
    return { labels, tld: "", tldLast: "", name: host, domain: host, subLabels: [], subdomain: "" };
  }
  const tld = labels.slice(-suffixLen).join(".");
  const subLabels = labels.slice(0, -(suffixLen + 1));
  return {
    labels, tld, tldLast: labels[labels.length - 1],
    name: labels[labels.length - suffixLen - 1],
    domain: labels.slice(-(suffixLen + 1)).join("."),
    subLabels, subdomain: subLabels.join(".")
  };
}

// Get just the host of a URL string (or "" if it isn't an http/https URL).
function hostOfUrl(href) {
  try {
    const u = new URL(href);
    return /^https?:$/.test(u.protocol) ? u.hostname.toLowerCase().replace(/^www\./, "") : "";
  } catch (e) { return ""; }
}

/* ---------- PARSE A URL ----------
   Uses the browser's built-in URL tool. It ONLY reads the text. It never
   connects to the address. Returns {error} or an object "u" with all the parts. */
function parseInputUrl(rawInput) {
  const raw = rawInput.trim();
  if (raw === "") return { error: "Please paste a URL first." };
  if (/\s/.test(raw)) return { error: "A URL can't contain spaces. Paste only the link." };

  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
  let parsed;
  try {
    parsed = new URL(hasScheme ? raw : "https://" + raw); // no scheme given? assume https just for parsing
  } catch (e) {
    return { error: "That doesn't look like a valid URL. Check that you pasted the whole link." };
  }
  if (!["http:", "https:"].includes(parsed.protocol)) return { error: "Only web links (http:// or https://) can be checked." };

  const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
  const hostIsIp = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.startsWith("[");
  const parts = hostIsIp
    ? { labels: [host], tld: "", tldLast: "", name: host, domain: host, subLabels: [], subdomain: "" }
    : splitHost(host); // "www" counts as a normal subdomain

  // Decode %20 style codes so keywords can be found, then lowercase for matching.
  let decoded = parsed.pathname + parsed.search + parsed.hash;
  try { decoded = decodeURIComponent(decoded); } catch (e) { /* keep as is */ }

  const u = {
    raw, hasScheme, host, hostIsIp,
    protocol: parsed.protocol,
    username: parsed.username ? parsed.username + (parsed.password ? ":" + parsed.password : "") : "",
    port: parsed.port,
    pathname: parsed.pathname,
    search: parsed.search + parsed.hash,
    pathQuery: decoded.toLowerCase(),
    ...parts
  };

  // The URL as coloured pieces (used to highlight the suspicious part)
  u.segments = [{ key: "protocol", text: hasScheme ? parsed.protocol + "//" : "https://", assumed: !hasScheme }];
  if (u.username) u.segments.push({ key: "userinfo", text: u.username + "@" });
  if (u.subdomain) u.segments.push({ key: "subdomain", text: u.subdomain + "." });
  u.segments.push({ key: "domain", text: u.domain });
  if (u.port) u.segments.push({ key: "port", text: ":" + u.port });
  u.segments.push({ key: "path", text: u.pathname });
  if (u.search) u.segments.push({ key: "query", text: u.search });
  return u;
}

/* ---------- Find all regex matches (as text) in a string ---------- */
function regexMatches(text, pattern) {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  const re = new RegExp(pattern.source, flags);
  const found = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m[0].length === 0) { re.lastIndex++; continue; }
    found.push({ start: m.index, text: m[0] });
  }
  return found;
}

// Is a match negated, like "do NOT share your OTP"?
function isNegated(text, start) {
  const before = text.slice(Math.max(0, start - 30), start).toLowerCase();
  return /\b(?:do not|don't|dont|never|should not|shouldn't|will not|won't|not to)\b/.test(before);
}

function patternMatches(rule, text) {
  let hits = [];
  for (const p of rule.patterns) hits = hits.concat(regexMatches(text, p));
  if (rule.skipIfNegated) hits = hits.filter((h) => !isNegated(text, h.start));
  return [...new Set(hits.map((h) => h.text.trim()))];
}

/* ---------- RUN A LIST OF RULES on a context ----------
   Returns { flags, score (0–100), level } */
function levelFor(score, flagCount) {
  if (flagCount === 0) return "none";
  if (score >= LEVELS.phishing) return "phishing";
  if (score >= LEVELS.suspicious) return "suspicious";
  return "safe";
}

function runRules(rules, ctx) {
  const flags = [];
  let total = 0;
  for (const rule of rules) {
    let res = rule.test ? rule.test(ctx) : patternMatches(rule, ctx.scanText);
    if (!res || (Array.isArray(res) && res.length === 0)) continue;
    if (res === true) res = { found: [] };
    if (Array.isArray(res)) res = { found: res };
    const weight = res.weight !== undefined ? res.weight : rule.weight;
    total += weight;
    flags.push({
      id: rule.id, title: rule.title, icon: rule.icon, weight, why: rule.why, tip: rule.tip,
      found: res.found || [], highlight: res.highlight || rule.highlight || []
    });
  }
  flags.sort((a, b) => b.weight - a.weight); // biggest red flags first
  const score = Math.min(100, total);
  return { flags, score, level: levelFor(score, flags.length) };
}

/* ---------- MAIN FUNCTION 1: analyse a URL ---------- */
function analyzeUrl(rawInput) {
  const u = parseInputUrl(rawInput);
  if (u.error) return { error: u.error };
  return { url: u, ...runRules(URL_RULES, u) };
}

/* ---------- Email helpers ---------- */

// All the links found in a piece of text. Returns a list of unique URL strings.
const COMMON_TLDS = ["com", "in", "co.in", "net", "org", "gov.in", "nic.in", "info", "co", "us", "biz", "ly", "gl", "me", "app", "shop", "store", "id", "is", "ee"];
const LINK_TLDS = [...new Set([...COMMON_TLDS, ...SUSPICIOUS_TLDS])].sort((a, b) => b.length - a.length).join("|");
const LINK_REGEX = new RegExp(
  "(?:https?:\\/\\/|www\\.)[^\\s<>\"')\\]]+" +                                   // starts with http://, https:// or www.
  "|\\b[a-z0-9][a-z0-9-]*(?:\\.[a-z0-9][a-z0-9-]*)*\\.(?:" + LINK_TLDS + ")" +   // or a bare name like bit.ly/abc
  "(?::\\d+)?(?:\\/[^\\s<>\"')\\]]*)?(?![a-z0-9-])",
  "gi"
);

function extractUrls(text) {
  const urls = [];
  for (const m of text.matchAll(LINK_REGEX)) {
    if (m.index > 0 && text[m.index - 1] === "@") continue; // part of an email address, not a link
    const url = m[0].replace(/[.,;:!?)\]]+$/, "");           // drop punctuation stuck to the end
    if (!urls.some((x) => x.toLowerCase() === url.toLowerCase())) urls.push(url);
  }
  return urls;
}

// Split "SBI Bank <alerts@sbi.co.in>" into display name + address.
function parseSender(raw) {
  const s = raw.trim();
  if (!s) return { displayName: "", address: "", localPart: "", domain: "" };
  let displayName = "", address = "";
  const m = s.match(/^(.*?)<\s*([^<>\s]+@[^<>\s]+)\s*>\s*$/);
  if (m) {
    displayName = m[1].replace(/^["'\s]+|["'\s]+$/g, "");
    address = m[2];
  } else {
    const a = s.match(/[^\s<>"']+@[^\s<>"']+/);
    address = a ? a[0] : "";
    displayName = s.replace(address, "").replace(/[<>"']/g, "").trim();
  }
  const at = address.lastIndexOf("@");
  return {
    displayName, address,
    localPart: at > -1 ? address.slice(0, at).toLowerCase() : "",
    domain: at > -1 ? address.slice(at + 1).toLowerCase().replace(/\.$/, "") : ""
  };
}

// Compare the display name / address with the claimed brand. Returns text or null.
function findSenderMismatch(e) {
  if (!e.domain) return null;
  // Trick 1: the display name itself shows a different email address
  const shownEmail = e.displayName.match(/[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/);
  if (shownEmail && splitHost(shownEmail[1].toLowerCase()).domain !== splitHost(e.domain).domain) {
    return `name shows “${shownEmail[0]}” but the real sender is ${e.address}`;
  }
  // Trick 2: the name or address claims to be a brand but the domain isn't theirs
  for (const brand of brandsInText(e.displayName + " " + e.localPart)) {
    if (!isOfficialFor(e.domain, brand)) return `claims to be ${brand.name} but the email comes from “${e.domain}”`;
  }
  return null;
}

/* ---------- Parse the email body (plain text OR pasted HTML) ----------
   For HTML we use DOMParser. It builds an INERT document: scripts don't run and
   images/links are never loaded, so this is safe. */
function parseEmailBody(body) {
  const looksLikeHtml = /<\s*(?:a|html|body|div|p|table|span|br|img|b|strong)\b[^>]*>/i.test(body);
  if (!looksLikeHtml) return { isHtml: false, text: body, anchors: [] };
  const spaced = body.replace(/<\/(?:p|div|li|tr|h[1-6])>|<br\s*\/?>/gi, "$&\n"); // keep line breaks
  const doc = new DOMParser().parseFromString(spaced, "text/html");
  const anchors = [...doc.querySelectorAll("a[href]")]
    .map((a) => ({ href: a.getAttribute("href").trim(), text: a.textContent.trim() }))
    .filter((a) => /^https?:\/\//i.test(a.href));
  doc.querySelectorAll("script, style").forEach((n) => n.remove());
  return { isHtml: true, text: doc.body.textContent, anchors };
}

/* ---------- Build everything the email rules need ---------- */
function buildEmailContext(from, subject, body) {
  const sender = parseSender(from);
  const parsedBody = parseEmailBody(body);
  const bodyText = parsedBody.text;
  const fullText = subject + "\n" + bodyText;

  // Every link: the ones in HTML anchors + the ones written in the text. Each is analysed with URL_RULES.
  const urlList = [...parsedBody.anchors.map((a) => a.href), ...extractUrls(fullText)];
  const unique = urlList.filter((x, i) => urlList.findIndex((y) => y.toLowerCase() === x.toLowerCase()) === i).slice(0, MAX_LINKS_CHECKED);
  const linkResults = [];
  for (const url of unique) {
    const r = analyzeUrl(url);
    if (!r.error) linkResults.push({ url, score: r.score, level: r.level, flags: r.flags });
  }

  return {
    ...sender, subject, bodyText, isHtml: parsedBody.isHtml, anchors: parsedBody.anchors,
    scanText: fullText,
    textNoUrls: fullText.replace(LINK_REGEX, " "), // text with links removed (so "index.html" in a URL isn't an attachment)
    linkResults
  };
}

/* ---------- MAIN FUNCTION 2: analyse an email ---------- */
function analyzeEmail(from, subject, body) {
  if (body.trim() === "") return { error: "Please paste the email body first." };
  const ctx = buildEmailContext(from, subject.trim(), body);
  return { email: ctx, ...runRules(EMAIL_RULES, ctx) };
}

/* =====================================================================
   PART 6: USER INTERFACE
   Everything below talks to the web page (the DOM). It only runs in a browser.
   ===================================================================== */

/* Tiny helper to build page elements safely.
   h("p", {class:"x", text:"hello"}, child1, child2)
   - "text" is set with textContent, so it can never run as HTML (no XSS).
   - children given as plain strings become text nodes (also safe). */
function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else node.setAttribute(key, value);
  }
  for (const child of children.flat()) if (child) node.append(child);
  return node;
}

const LEVEL_TEXT = {
  none:       { badge: "No red flags", head: "No obvious red flags", sum: "Nothing suspicious was found by our rules. That doesn't prove it is safe, so stay careful." },
  safe:       { badge: "Safe-looking", head: "Looks mostly safe, with small warnings", sum: "Only minor warning signs were found. Still, read the flags below before trusting it." },
  suspicious: { badge: "Suspicious", head: "Be careful: this looks suspicious", sum: "Several phishing-like features were found. Don't click, download or enter any details until you've verified it independently." },
  phishing:   { badge: "Likely phishing", head: "Very likely phishing!", sum: "This matches many known phishing tricks. Do not click, open attachments, reply or enter any information." }
};

const URL_ADVICE = [
  "Don't open or click this link, and don't visit it “just to see”.",
  "Never type passwords, OTPs, card or UPI details on a page you reached from a message.",
  "To reach the real website, type its address yourself or use the official app from the app store.",
  "Delete the message and block the sender.",
  "Report it: call 1930, visit cybercrime.gov.in, or report to CERT-In."
];
const EMAIL_ADVICE = [
  "Don't click any link in the email.",
  "Don't open or download any attachment.",
  "Don't reply, and don't call numbers given in the email.",
  "Report it: forward it to the bank or company it pretends to be (use the “report phishing” address on their real website) or use “Report phishing” in your email app. Also report at cybercrime.gov.in or CERT-In.",
  "Delete the email and block the sender."
];

// Explanations of each part of a URL (shown in the breakdown)
const PART_INFO = {
  protocol:  { label: "Protocol", help: "How your browser connects. https:// is encrypted; http:// is not." },
  userinfo:  { label: "Username (before @)", help: "The browser IGNORES this when deciding where to go. Scammers put a fake name here." },
  subdomain: { label: "Subdomain", help: "Words in front of the main domain. Anyone who owns a domain can create any subdomain they like, so scammers put bank names here." },
  domain:    { label: "Domain (the real website)", help: "This is the part that matters. It decides who really owns the page." },
  port:      { label: "Port", help: "A technical number. Normal sites don't show one." },
  path:      { label: "Path", help: "The page or file on that website. It can say anything, so it proves nothing about who runs the site." },
  query:     { label: "Query / fragment", help: "Extra data after “?” or “#”, often tracking codes or account IDs." }
};

if (typeof document !== "undefined") {
  document.documentElement.classList.add("js"); // tells the CSS that JavaScript works

  const $ = (id) => document.getElementById(id);
  const resultsBox = $("results");
  const METER_LENGTH = 326.73; // ring circumference = 2 × π × 52 (must match style.css)

  /* ---------- Draw the URL breakdown (protocol / subdomain / domain / path…) ---------- */
  function renderUrlBreakdown(u, flags, container) {
    // Which parts were flagged, and by which rules?
    const bad = {};
    for (const f of flags) for (const key of f.highlight) (bad[key] = bad[key] || []).push(f.title);

    // 1) The URL as coloured pieces. We use <code> + <span> (NOT a link) so it can't be clicked.
    const line = h("code", { class: "url-line", "aria-label": "The URL split into parts" });
    for (const seg of u.segments) {
      line.append(h("span", {
        class: "seg seg-" + seg.key + (bad[seg.key] ? " bad" : "") + (seg.assumed ? " assumed" : ""),
        title: bad[seg.key] ? "Suspicious: " + bad[seg.key].join("; ") : PART_INFO[seg.key].label,
        text: seg.text
      }));
    }
    container.append(
      h("p", { class: "muted small", text: "Here is how your browser reads this address. Highlighted parts are suspicious. Hover over a part for details." }),
      line
    );

    // 2) A list explaining each part
    const rows = [
      ["protocol", u.segments[0].assumed ? "https:// (none given, assumed)" : u.protocol + "//"],
      u.username ? ["userinfo", u.username + "@"] : null,
      ["subdomain", u.subdomain ? u.subdomain : "(none)"],
      ["domain", u.domain],
      u.port ? ["port", ":" + u.port] : null,
      ["path", u.pathname],
      u.search ? ["query", u.search] : null
    ].filter(Boolean);

    const list = h("dl", { class: "parts" });
    for (const [key, value] of rows) {
      const row = h("div", { class: "part-row" + (bad[key] ? " bad" : "") },
        h("dt", { text: PART_INFO[key].label }),
        h("dd", {}, h("code", { text: value }), h("span", { class: "part-help", text: PART_INFO[key].help }))
      );
      if (bad[key]) row.lastChild.append(h("span", { class: "part-warn", text: "⚠ " + bad[key].join(" · ") }));
      list.append(row);
    }
    container.append(list);
  }

  /* ---------- Draw the email details + the list of links found ---------- */
  function renderEmailDetails(e, container) {
    const info = h("dl", { class: "parts" });
    const add = (label, value, note) => info.append(
      h("div", { class: "part-row" }, h("dt", { text: label }),
        h("dd", {}, h("code", { text: value || "(not given)" }), note ? h("span", { class: "part-help", text: note }) : null))
    );
    add("Display name", e.displayName, "Anyone can type any name here. It proves nothing.");
    add("Sender address", e.address, "The part after the @ is the real sender.");
    add("Sender domain", e.domain);
    add("Subject", e.subject);
    add("Body format", e.isHtml ? "HTML (link texts were compared with real destinations)" : "Plain text");
    container.append(info);

    container.append(h("h4", { class: "sub-title", text: "Links found in the email (" + e.linkResults.length + ")" }));
    if (e.linkResults.length === 0) {
      container.append(h("p", { class: "muted", text: "No links were found." }));
      return;
    }
    const ul = h("ul", { class: "link-list" });
    for (const l of e.linkResults) {
      ul.append(h("li", { class: "link-item lv-" + l.level },
        h("code", { class: "plain-url", text: l.url }),
        h("span", { class: "mini-badge", text: l.score + "% · " + LEVEL_TEXT[l.level].badge }),
        l.flags.length ? h("span", { class: "link-flags muted small", text: l.flags.map((f) => f.title).join(" · ") }) : null
      ));
    }
    container.append(ul, h("p", { class: "muted small", text: "Links are shown as plain text on purpose, so they can't be clicked by accident." }));
  }

  /* ---------- Draw the "Red flags found" list ---------- */
  function renderFlags(flags) {
    const list = $("flagList");
    list.replaceChildren();
    flags.forEach((f, i) => {
      const item = h("li", { class: "flag-item sev-" + (f.weight >= 20 ? "high" : "med") });
      item.style.animationDelay = i * 70 + "ms"; // appear one after another
      const body = h("div", {},
        h("div", { class: "flag-head" }, h("span", { class: "flag-title", text: f.title }), h("span", { class: "flag-points", text: "+" + f.weight + " points" })),
        h("p", { class: "flag-why", text: f.why })
      );
      const found = f.found.slice(0, 4);
      if (found.length) {
        const chips = h("div", { class: "flag-found" }, h("span", { class: "muted", text: "Found:" }));
        for (const t of found) chips.append(h("span", { class: "found-chip", text: t.length > 80 ? t.slice(0, 77) + "…" : t }));
        body.append(chips);
      }
      item.append(h("span", { class: "flag-icon", "aria-hidden": "true", text: f.icon }), body);
      list.append(item);
    });
  }

  /* ---------- Show a full result on screen ---------- */
  function showResult(analysis, mode) {
    const t = LEVEL_TEXT[analysis.level];
    resultsBox.className = "results level-" + analysis.level;
    resultsBox.hidden = false;
    $("riskBadge").textContent = t.badge;
    $("riskHeadline").textContent = t.head;
    $("riskSummary").textContent = t.sum;
    animateMeter(analysis.score);

    const none = analysis.level === "none";
    $("safeCard").hidden = !none;
    $("flagsCard").hidden = none;
    $("adviceCard").hidden = none;

    // Parsed details
    const body = $("parsedBody");
    body.replaceChildren();
    if (mode === "url") {
      $("parsedTitle").textContent = "🧩 How this URL is built";
      renderUrlBreakdown(analysis.url, analysis.flags, body);
    } else {
      $("parsedTitle").textContent = "📬 What was found in this email";
      renderEmailDetails(analysis.email, body);
    }

    if (!none) {
      renderFlags(analysis.flags);
      const tips = [...new Set(analysis.flags.map((f) => f.tip).filter(Boolean))].slice(0, 3);
      const advice = $("adviceList");
      advice.replaceChildren();
      [...tips, ...(mode === "url" ? URL_ADVICE : EMAIL_ADVICE)].forEach((txt) => advice.append(h("li", { text: txt })));
    }
    resultsBox.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  /* ---------- Animate the ring, the bar and the counting number ---------- */
  function animateMeter(score) {
    const fill = $("meterFill"), bar = $("barFill");
    fill.style.transition = "none"; bar.style.transition = "none"; // reset so it replays every time
    fill.style.strokeDashoffset = METER_LENGTH; bar.style.width = "0%";
    void fill.getBoundingClientRect(); // forces the browser to apply the reset
    fill.style.transition = ""; bar.style.transition = "";
    fill.style.strokeDashoffset = METER_LENGTH * (1 - score / 100);
    bar.style.width = score + "%";
    $("riskBar").setAttribute("aria-valuenow", score);

    const label = $("riskPercent"), start = performance.now(), duration = 1000;
    (function tick(now) {
      const p = Math.min(1, (now - start) / duration);
      label.textContent = Math.round(score * (1 - Math.pow(1 - p, 3))); // ease-out
      if (p < 1) requestAnimationFrame(tick);
    })(start);
  }

  /* ---------- URL tab buttons ---------- */
  const urlInput = $("urlInput");
  function onCheckUrl() {
    const analysis = analyzeUrl(urlInput.value);
    if (analysis.error) { $("urlError").textContent = analysis.error; resultsBox.hidden = true; urlInput.focus(); return; }
    $("urlError").textContent = "";
    showResult(analysis, "url");
  }
  $("checkUrlBtn").addEventListener("click", onCheckUrl);
  urlInput.addEventListener("keydown", (ev) => { if (ev.key === "Enter") onCheckUrl(); });
  urlInput.addEventListener("input", () => { $("urlError").textContent = ""; });
  $("clearUrlBtn").addEventListener("click", () => {
    urlInput.value = ""; $("urlError").textContent = ""; resultsBox.hidden = true; urlInput.focus();
  });

  /* ---------- Email tab buttons ---------- */
  function onCheckEmail() {
    const analysis = analyzeEmail($("emailFrom").value, $("emailSubject").value, $("emailBody").value);
    if (analysis.error) { $("emailError").textContent = analysis.error; resultsBox.hidden = true; $("emailBody").focus(); return; }
    $("emailError").textContent = "";
    showResult(analysis, "email");
  }
  $("checkEmailBtn").addEventListener("click", onCheckEmail);
  $("clearEmailBtn").addEventListener("click", () => {
    ["emailFrom", "emailSubject", "emailBody"].forEach((id) => { $(id).value = ""; });
    $("emailError").textContent = ""; resultsBox.hidden = true; $("emailFrom").focus();
  });
  $("emailBody").addEventListener("input", () => { $("emailError").textContent = ""; });

  /* ---------- Tabs ---------- */
  const tabs = { url: { tab: $("tabUrl"), panel: $("panelUrl") }, email: { tab: $("tabEmail"), panel: $("panelEmail") } };
  function selectTab(name, moveFocus) {
    for (const [key, { tab, panel }] of Object.entries(tabs)) {
      const active = key === name;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", String(active));
      tab.tabIndex = active ? 0 : -1;
      panel.hidden = !active;
    }
    resultsBox.hidden = true; // an old result doesn't belong to the other tab
    if (moveFocus) tabs[name].tab.focus();
  }
  tabs.url.tab.addEventListener("click", () => selectTab("url"));
  tabs.email.tab.addEventListener("click", () => selectTab("email"));
  // Arrow keys switch tabs (keyboard accessibility)
  [tabs.url.tab, tabs.email.tab].forEach((tab) =>
    tab.addEventListener("keydown", (ev) => {
      if (ev.key === "ArrowRight" || ev.key === "ArrowLeft") selectTab(tab === tabs.url.tab ? "email" : "url", true);
    })
  );

  /* ---------- Example buttons (made from the EXAMPLES array) ---------- */
  const exampleBox = $("exampleButtons");
  EXAMPLES.forEach((ex) => {
    const btn = h("button", { type: "button", class: "chip", text: ex.label });
    btn.addEventListener("click", () => {
      selectTab(ex.mode);
      if (ex.mode === "url") {
        urlInput.value = ex.url;
        $("urlError").textContent = "";
      } else {
        $("emailFrom").value = ex.from;
        $("emailSubject").value = ex.subject;
        $("emailBody").value = ex.body;
        $("emailError").textContent = "";
      }
      $("checker").scrollIntoView({ behavior: "smooth", block: "start" });
    });
    exampleBox.append(btn);
  });

  /* ---------- "How it works": rule lists generated from the arrays ---------- */
  function fillRuleList(id, rules) {
    const ul = $(id);
    rules.forEach((r) => ul.append(h("li", {}, h("span", { "aria-hidden": "true", text: r.icon }), " " + r.title + " ", h("span", { class: "pts", text: "+" + r.weight }))));
  }
  fillRuleList("urlRulesList", URL_RULES);
  fillRuleList("emailRulesList", EMAIL_RULES);

  /* ---------- Dark / light mode (remembered in localStorage) ---------- */
  const root = document.documentElement, themeBtn = $("themeToggle");
  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    themeBtn.querySelector(".theme-icon").textContent = theme === "dark" ? "☀️" : "🌙";
    themeBtn.setAttribute("aria-label", theme === "dark" ? "Switch to light mode" : "Switch to dark mode");
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", theme === "dark" ? "#050b1c" : "#eef4ff");
  }
  let saved = null;
  try { saved = localStorage.getItem("phishguard-theme"); } catch (err) { /* storage blocked */ }
  applyTheme(saved === "light" ? "light" : "dark");
  themeBtn.addEventListener("click", () => {
    const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    applyTheme(next);
    try { localStorage.setItem("phishguard-theme", next); } catch (err) { /* ignore */ }
  });

  /* ---------- Mobile menu ---------- */
  const menuBtn = $("menuToggle"), nav = $("mainNav");
  menuBtn.addEventListener("click", () => menuBtn.setAttribute("aria-expanded", String(nav.classList.toggle("open"))));
  nav.querySelectorAll("a").forEach((a) => a.addEventListener("click", () => { nav.classList.remove("open"); menuBtn.setAttribute("aria-expanded", "false"); }));

  /* ---------- Scroll-reveal animation ---------- */
  const revealEls = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((en) => { if (en.isIntersecting) { en.target.classList.add("visible"); observer.unobserve(en.target); } });
    }, { threshold: 0.12 });
    revealEls.forEach((el) => observer.observe(el));
  } else {
    revealEls.forEach((el) => el.classList.add("visible"));
  }
}
