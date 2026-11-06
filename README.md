# Phishing_Email_Analyser

A simple, educational web tool that checks a pasted email for common phishing warning signs and explains exactly why it gave the score it did.

Everything runs in your browser. Your email is never uploaded, stored or tracked.

> **Disclaimer:** This is an educational triage tool. It looks for warning signs and **cannot prove** an email is safe or malicious. Never click suspicious links or open attachments to test them. Verify important messages through an official website, app or a contact you already trust.

## Features

- Paste an email (with or without headers) and click **Analyse Email**
- Risk score from 0 to 100 with a clear band: **Low Risk**, **Suspicious** or **High Risk**
- Every triggered rule is listed with its points, a plain-English explanation and the matched text
- Practical "what to do next" advice based on what was found
- Six fictional example emails you can load with one click
- Responsive design for desktop and mobile


- No server, database, AI service, analytics or tracking
- No network requests: the page includes a Content Security Policy (`connect-src 'none'`) that tells the browser to block them
- Results are displayed with `textContent`, so pasted text cannot run as code
- Closing or refreshing the tab erases what you pasted

## Privacy

- No server, database, AI service, analytics or tracking
- No network requests: the page includes a Content Security Policy (connect-src 'none') that tells the browser to block them
- Results are displayed with textContent, so pasted text cannot run as code
- Closing or refreshing the tab erases what you pasted

## How to run

1. Download or clone this repository
2. Open `index.html` in any modern browser

No installation or build step is needed. It also works on GitHub Pages or Netlify: just publish the folder.

## How the score works

Each warning sign is a named rule with a fixed point value. The score is the sum of all triggered rules, capped at 100.

| Score | Result |
|---|---|
| 0-29 | Low Risk |
| 30-59 | Suspicious |
| 60-100 | High Risk |

### Rules

| Rule | Points |
|---|---|
| Request for your password | 25 |
| Request for a verification / MFA code | 25 |
| Request to change bank details | 25 |
| Executable attachment type (.exe, .js, .bat ...) | 25 |
| Payment, fee or gift-card request | 20 |
| Link uses a raw IP address | 20 |
| Link text does not match where it goes | 20 |
| Request to enable macros or editing | 20 |
| Threat of account suspension or closure | 15 |
| Unusual attachment (double extension, archive, HTML) | 15 |
| Sender and Reply-To domains do not match | 15 |
| SPF check failed | 15 |
| DMARC check failed | 15 |
| Suspicious-looking link address | 12 |
| Credential-harvesting language | 12 |
| Urgency and pressure language | 10 |
| Shortened URL | 10 |
| Impersonation language | 10 |
| DKIM check failed | 10 |
| Invoice or payment-notice language | 8 |
| Generic greeting | 5 |

For the deeper checks (Reply-To, SPF, DKIM, DMARC), include the email headers when you paste.

## Project structure

```
index.html   Page structure, privacy and safety notices
style.css    Styling
app.js       Scoring rules, example emails and interface code
```

To change a point value or add a rule, edit the `RULES` list in `app.js`.

## Example emails

All examples are fictional and use reserved fake domains with no working links:

1. Obvious phishing
2. Sophisticated phishing
3. Fake Microsoft 365 warning
4. Fake parcel delivery
5. Fake invoice / business email compromise
6. Legitimate email

## Limitations

- Rule-based pattern matching can miss cleverly worded attacks and can occasionally flag legitimate emails
- It does not open links, scan attachments or check domain reputation
- A low score is not proof of safety