# 🪝 PhishGuard: Phishing URL & Email Checker

PhishGuard is a small website that checks a suspicious **URL** or the text of a suspicious **email** and shows **how likely it is to be phishing, and why**, in simple language. It includes examples relevant to India (SBI, HDFC, ICICI, Paytm, PhonePe, Income Tax, Aadhaar, India Post).

It is built with only **HTML, CSS and vanilla JavaScript**: no frameworks, no backend, no API calls.

> 🔒 **Privacy & safety:** everything runs locally in your browser. Nothing you paste is stored or sent anywhere. PhishGuard **never opens, fetches or visits** a pasted URL: it only analyses the text of it. Pasted URLs are shown as plain text (not clickable), and all user input is displayed with `textContent` (never `innerHTML`) to prevent XSS.

## ✨ Features

**Two modes (tabs)**

- **URL Checker:** parses the URL with the browser's `URL` API and checks for HTTP instead of HTTPS, IP addresses instead of domain names, URL shorteners, too many subdomains, very long URLs, many hyphens/digits, `@` tricks, risky endings (`.xyz`, `.top`, `.tk`, `.click`, `.work`, `.ml`, `.ga`…), brand names inside non-official domains (`sbi-kyc-update.xyz`), typosquatting / lookalikes (`paypa1.com`, `amaz0n.in`, `hdfcbamk.com`) using a Levenshtein distance function, suspicious path keywords (`login`, `verify`, `kyc`, `otp`, `reward`…), Punycode (`xn--`) domains and `.apk` / `.exe` / `.zip` downloads.
- **Email Checker:** paste the sender, subject and body (plain text or HTML). Checks sender/display-name mismatch, fake sender domains, urgency and threats, requests for passwords/OTP/PIN/Aadhaar/PAN/card details, generic greetings, every link in the body (each one is run through the URL rules), link text that doesn't match the real destination (HTML), risky attachments and macros, prize/refund claims, spelling mistakes, capital letters and exclamation marks.

**Results**

- Risk score from **0 to 100%** with an animated meter
- Badge: **Safe-looking** (green), **Suspicious** (orange), **Likely phishing** (red)
- **"Red flags found"** list with a plain-English explanation for each
- **URL breakdown** (protocol, subdomain, domain, path, query) with the suspicious part highlighted
- **"What you should do"** advice
- **"No obvious red flags"** result with a reminder that no tool is 100% accurate
- 6 **"Try an example"** buttons (fake SBI KYC URL, typosquatted Amazon link, fake Income Tax refund email, fake India Post delivery email, shortened link, and a safe URL)
- **How to spot phishing** tips, with safe-vs-fake URL comparisons
- **Report phishing** info: 1930 helpline, cybercrime.gov.in, CERT-In, your bank / email provider, plus links to **Google Safe Browsing** and **VirusTotal** for manual double-checking (links only, no API calls)
- Dark / light mode, responsive layout for mobile and desktop

## 🚀 How to run

No installation needed.

1. Download or clone this repository.
2. Double-click `index.html` to open it in a modern browser.

**Deploy on GitHub Pages:** repository **Settings → Pages → Deploy from a branch → `main` / `(root)` → Save**.

## 📁 Project structure

| File | What it does |
| --- | --- |
| `index.html` | Page structure: header, checker (tabs), how it works, tips, report, footer |
| `style.css` | All styling, including dark/light themes and responsive layout |
| `script.js` | Lists (brands, TLDs, keywords), the URL and email rules, the scoring engine and the UI |

## 🧮 How the scoring works

1. Each rule in `URL_RULES` / `EMAIL_RULES` has a **weight** (points) and a `test` function (or regex `patterns`).
2. Every rule that triggers becomes a **red flag** and adds its points **once**. (A few rules adjust their points, for example the email "suspicious link" rule scales with how bad the worst link is.)
3. The total is capped at **100** and shown as a percentage.

| Score | Level |
| --- | --- |
| no flags | No obvious red flags |
| 1–24% | Safe-looking |
| 25–59% | Suspicious |
| 60–100% | Likely phishing |

Examples of weights: brand name in a non-official domain **+35**, typosquatted brand **+40**, IP address host **+35**, shortened link **+30**, risky ending **+20**, HTTP **+15**. In emails: sender mismatch **+35**, asks for OTP/PIN/passwords **+35**, risky attachment **+30**, urgency **+15**.

### Typosquatting detection

`findTyposquat()` compares the domain name (and each hyphen-separated piece) with popular brand names using **Levenshtein distance** (the number of single-letter changes needed to turn one word into another; 1 change allowed for short names, 2 for long ones). It also undoes common look-alike tricks (`0→o`, `1→l/i`, `rn→m`, `vv→w`).

### Adding your own rule

Open `script.js` and add an object to `URL_RULES` or `EMAIL_RULES`:

```js
{
  id: "bad-port", title: "Unusual port number", icon: "🚪", weight: 8, highlight: ["port"],
  why: "Normal websites don't show a port number.",
  test: (u) => u.port !== "" && !["80", "443"].includes(u.port) && { found: [":" + u.port] }
}
```

To add a brand, edit the `BRANDS` array. To add risky endings or keywords, edit `SUSPICIOUS_TLDS` or `PATH_KEYWORDS`. All lists are at the top of the file.

## ⚠️ Limitations

- It is **rule-based**. It **cannot check live reputation** (whether a site is on a blocklist) or **domain age** (new domains are a strong phishing signal), and it never visits the link.
- New or clever phishing may score low (**the link may still be unsafe**), and genuine messages can sometimes be flagged. No tool is 100% accurate.
- Brand lists are small and focused on India and popular global brands.
- It reads **text only**: it can't see images, QR codes, real email headers (SPF/DKIM) or attachment contents.
- It mainly understands English.

## 🔮 Future improvements

- **Google Safe Browsing API** integration for live reputation (needs a backend or API key handling)
- **WHOIS / domain-age check** (very new domains are suspicious)
- A **browser extension** that checks links and emails as you browse
- Email **header analysis** (SPF, DKIM, DMARC, Reply-To mismatch)
- A **machine learning model** trained on phishing URLs, combined with the rules
- QR-code scanner ("quishing") and Hindi language support
- Unit tests for every rule

## 📞 Report phishing (India)

- Helpline: **1930**
- Portal: <https://cybercrime.gov.in>
- CERT-In: <https://www.cert-in.org.in>
- Forward phishing emails to the bank they imitate, and use "Report phishing" in your email app.

## 📄 License

Free to use for learning and education.
