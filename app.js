/* Phishing Email Analyser. Runs only in the browser. No network calls, no storage, no tracking.
   Every rule below has a fixed point value. Score = sum of triggered rules, capped at 100.
   Bands: 0-29 Low Risk, 30-59 Suspicious, 60-100 High Risk. */
(function (root) {
  'use strict';

  var SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at'];
  var BRANDS = { microsoft: ['microsoft.com', 'microsoftonline.com', 'office.com', 'live.com', 'office365.com'], office365: ['office.com', 'office365.com', 'microsoft.com'], paypal: ['paypal.com'], apple: ['apple.com', 'icloud.com'], icloud: ['icloud.com', 'apple.com'], amazon: ['amazon.com'], google: ['google.com'], netflix: ['netflix.com'], dhl: ['dhl.com'], fedex: ['fedex.com'] };
  var EXEC = 'exe|scr|bat|cmd|js|jse|vbs|vbe|wsf|ps1|msi|jar|hta|lnk|iso|img|dll|reg|apk';

  function uniq(a) { return a.filter(function (x, i) { return a.indexOf(x) === i; }); }
  function clip(s) { s = s.replace(/\s+/g, ' ').trim(); return s.length > 90 ? s.slice(0, 87) + '...' : s; }
  function regDomain(h) { return h.split('.').slice(-2).join('.'); }
  function onDomain(host, d) { return host === d || host.slice(-d.length - 1) === '.' + d; }

  // Prepare everything the rules need once.
  function prepare(raw) {
    var ctx = { raw: raw };
    ctx.sentences = raw.split(/(?<=[.!?])\s+|\n+/).map(function (s) { return s.trim(); }).filter(Boolean);
    var from = /^from:.*$/im.exec(raw), reply = /^reply-to:.*$/im.exec(raw);
    var em = function (m) { var x = m && /([\w.+-]+)@([\w.-]+\.[a-z]{2,})/i.exec(m[0]); return x ? { addr: x[0], domain: x[2].toLowerCase() } : null; };
    ctx.from = em(from); ctx.reply = em(reply);

    var urls = (raw.match(/\bhttps?:\/\/[^\s<>"')\]]+|\bwww\.[^\s<>"')\]]+/gi) || [])
      .concat(raw.match(new RegExp('\\b(?:' + SHORTENERS.join('|').replace(/\./g, '\\.') + ')\\/[^\\s<>"\')\\]]+', 'gi')) || []);
    ctx.urls = [];
    uniq(urls.map(function (u) { return u.replace(/[.,;:!?]+$/, ''); })).forEach(function (u) {
      try { var p = new URL(/^https?:/i.test(u) ? u : 'http://' + u); ctx.urls.push({ text: u, host: p.hostname.toLowerCase(), user: p.username }); } catch (e) { /* ignore unparsable */ }
    });

    // Text without URLs and email addresses, used for attachment filename scanning.
    ctx.plain = raw.replace(/\bhttps?:\/\/\S+|\bwww\.\S+/gi, ' ').replace(/[\w.+-]+@[\w.-]+/g, ' ');
    var from_ = ctx.from ? ctx.from.domain : '';
    ctx.fromDomain = from_;
    return ctx;
  }

  function scan(ctx, re) { var m = ctx.raw.match(re) || []; return uniq(m.map(clip)).slice(0, 4); }
  function both(ctx, verbRe, topicRe) { return uniq(ctx.sentences.filter(function (s) { return verbRe.test(s) && topicRe.test(s); }).map(clip)).slice(0, 3); }
  function hosts(ctx, fn) { return uniq(ctx.urls.filter(fn).map(function (u) { return u.host; })).slice(0, 4); }

  var RULES = [
    { id: 'urgency', name: 'Urgency and pressure language', points: 10,
      why: 'Scammers rush you so you act before thinking. Real organisations rarely demand action within hours.',
      detect: function (c) { return scan(c, /\b(urgent(ly)?|immediately|act now|right away|within \d+ ?(hours?|minutes?)|final (notice|warning|reminder)|expires? (today|soon|in)|last chance|time[- ]sensitive|as soon as possible|asap|are you at your desk)\b/gi); } },
    { id: 'threat', name: 'Threat of account suspension or closure', points: 15,
      why: 'Threatening to lock, close or delete something you value is a classic way to scare people into clicking.',
      detect: function (c) { return scan(c, /(account (will be|has been|is|may be) (suspended|closed|locked|disabled|terminated|deactivated|restricted)|(suspend|close|terminate|deactivate|lock|restrict)(ed|ion)? (of )?your (account|mailbox|access)|permanent(ly)? (closed|deleted|disabled)|legal action|lose access|unauthori[sz]ed (access|activity|sign[- ]?in)|will be (deleted|removed))/gi); } },
    { id: 'password', name: 'Request for your password', points: 25,
      why: 'Legitimate services never ask you to send or type your password in reply to an email.',
      detect: function (c) { return both(c, /\b(enter|confirm|verify|provide|send|reply|update|re-?enter|share|keep)\b/i, /\b(password|passcode|login credentials|sign[- ]?in details)\b/i); } },
    { id: 'mfa', name: 'Request for a verification or MFA code', points: 25,
      why: 'One-time codes exist to stop attackers. Anyone asking you to read one out or send it on is trying to get past that protection.',
      detect: function (c) { return both(c, /\b(send|reply|share|provide|enter|read|forward|tell|give|confirm|approve)\b/i, /(verification code|one[- ]time (code|password)|\botp\b|security code|authenticat(or|ion) code|\b2fa\b|\bmfa\b|\d-digit code|sign[- ]?in request)/i); } },
    { id: 'payment', name: 'Payment, fee or gift-card request', points: 20,
      why: 'Gift cards, crypto, wire transfers and small "release fees" are hard to reverse, which is why scammers ask for them.',
      detect: function (c) { return scan(c, /(gift ?cards?|itunes card|google play card|steam card|wire transfer|bitcoin|cryptocurrency|western union|(redelivery|customs|delivery|release|handling|processing) fee|pay (now|immediately|the fee)|send (the )?money)/gi); } },
    { id: 'bank', name: 'Request to change bank details', points: 25,
      why: 'Changing who gets paid is the core move in business email compromise. Always confirm by phone using a number you already have.',
      detect: function (c) { return scan(c, /((new|updated|changed?|different) (bank|banking|payment) (details|account|information)|bank details? (have|has) (changed|been updated)|change (of )?bank|update (our|the|my) (bank|payment) (details|information)|pay (into|to) (the|our) new account)/gi); } },
    { id: 'shortlink', name: 'Shortened URL', points: 10,
      why: 'Link shorteners hide the real destination, so you cannot judge the link before you click.',
      detect: function (c) { return hosts(c, function (u) { return SHORTENERS.indexOf(u.host) > -1; }); } },
    { id: 'ipurl', name: 'Link uses a raw IP address', points: 20,
      why: 'Real companies use their own domain names. A bare number such as 203.0.113.45 usually means a throwaway server.',
      detect: function (c) { return hosts(c, function (u) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(u.host); }); } },
    { id: 'badurl', name: 'Suspicious-looking link address', points: 12,
      why: 'Look-alike names, odd characters, hidden user-info or stacked hyphens and keywords are common tricks to imitate a trusted site.',
      detect: function (c) {
        return hosts(c, function (u) {
          if (/^\d{1,3}(\.\d{1,3}){3}$/.test(u.host) || SHORTENERS.indexOf(u.host) > -1) return false;
          if (u.host.indexOf('xn--') > -1 || u.user || u.host.split('.').length >= 5) return true;
          if (/\.(zip|top|xyz|click|work|tk|ml|gq|cf)$/.test(u.host)) return true;
          var norm = u.host.replace(/1/g, 'l').replace(/0/g, 'o').replace(/3/g, 'e');
          for (var b in BRANDS) { if (norm.indexOf(b) > -1 && !BRANDS[b].some(function (d) { return onDomain(u.host, d); })) return true; }
          return (u.host.match(/-/g) || []).length >= 2 && /(secure|login|verify|account|update|support)/.test(u.host);
        });
      } },
    { id: 'mismatch', name: 'Link text does not match where it goes', points: 20,
      why: 'The words you see say one website, but the link underneath goes to another. Hover over links to check, never click to find out.',
      detect: function (c) {
        var out = [], m, re = /<a\s[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi, md = /\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g;
        function check(text, href) {
          var t = /([a-z0-9-]+(\.[a-z0-9-]+)+)/i.exec(text.replace(/<[^>]+>/g, '')), h;
          try { h = new URL(href).hostname.toLowerCase(); } catch (e) { return; }
          if (t && regDomain(t[1].toLowerCase()) !== regDomain(h)) out.push(clip('shows "' + t[1] + '" but goes to ' + h));
        }
        while ((m = re.exec(c.raw))) check(m[2], m[1]);
        while ((m = md.exec(c.raw))) check(m[1], m[2]);
        return out;
      } },
    { id: 'impersonation', name: 'Impersonation language', points: 10,
      why: 'Phishing borrows the name of a trusted brand or team (IT, security, billing) to look official.',
      detect: function (c) {
        var found = scan(c, /\b((it|security|billing|account|delivery|customer) (support|team|department|help ?desk)|help ?desk|system administrator|microsoft|office ?365|m365|paypal|apple id|icloud|amazon|google|netflix|dhl|fedex|hmrc|irs)\b/gi);
        if (!found.length) return [];
        var low = found.join(' ').toLowerCase(), team = /(team|department|desk|administrator)/.test(low);
        if (team) return found;
        return found.filter(function (f) { return !c.fromDomain || c.fromDomain.indexOf(f.toLowerCase().replace(/\s/g, '')) < 0; });
      } },
    { id: 'greeting', name: 'Generic greeting', points: 5,
      why: 'Messages that really come from your provider usually know your name.',
      detect: function (c) { return scan(c, /^(dear|hello|hi) (customer|user|client|member|account holder|valued \w+|sir|madam|sir\/madam)\b/gim); } },
    { id: 'attach_unusual', name: 'Unusual attachment filename', points: 15,
      why: 'Double extensions (invoice.pdf.exe) and archive or HTML attachments are used to sneak past filters and to trick you about the file type.',
      detect: function (c) { return scan({ raw: c.plain }, new RegExp('[\\w\\-. ()]{1,60}\\.(?:pdf|docx?|xlsx?|jpe?g|png|txt)\\.(?:' + EXEC + '|html?)\\b|[\\w\\-. ()]{1,60}\\.(?:zip|rar|7z|html?|shtml)\\b', 'gi')); } },
    { id: 'attach_exec', name: 'Executable attachment type', points: 25,
      why: 'Programs and scripts (.exe, .js, .bat and similar) can run code on your device the moment they are opened.',
      detect: function (c) { return scan({ raw: c.plain }, new RegExp('[\\w\\-. ()]{1,60}\\.(?:' + EXEC + ')\\b', 'gi')); } },
    { id: 'macro', name: 'Request to enable macros or editing', points: 20,
      why: 'Documents that ask you to "enable content" often hide malicious macros that only run once you allow them.',
      detect: function (c) { return scan(c, /(enable (editing|content|macros?)|macros? (must|need|has|have) (to be )?enabled|\.(docm|xlsm|pptm|dotm)\b)/gi); } },
    { id: 'invoice', name: 'Invoice or payment-notice language', points: 8,
      why: 'Fake invoices rely on you paying or opening the file without checking whether you actually ordered anything.',
      detect: function (c) { return scan(c, /\b(invoice|remittance advice|payment (advice|reminder)|purchase order|overdue (balance|invoice)|statement of account)\b/gi); } },
    { id: 'harvest', name: 'Credential-harvesting language', points: 12,
      why: 'Phrases like "verify your account" paired with a link are how fake login pages get visitors.',
      detect: function (c) { return both(c, /\b(log ?in|sign ?in|verify|confirm|validate|update|re-?activate)\b/i, /\b(your (account|identity|credentials|details|information|billing|mailbox)|account (details|information))\b/i); } },
    { id: 'replyto', name: 'Sender and Reply-To do not match', points: 15,
      why: 'Replies go to a different domain than the sender. That lets attackers spoof a trusted sender but still receive your answer.',
      detect: function (c) { return c.from && c.reply && regDomain(c.from.domain) !== regDomain(c.reply.domain) ? ['From ' + c.from.domain + ' / Reply-To ' + c.reply.domain] : []; } },
    { id: 'spf', name: 'SPF check failed', points: 15,
      why: 'SPF says whether the sending server is allowed to send for that domain. A failure suggests a forged sender.',
      detect: function (c) { return scan(c, /(spf=(fail|softfail)|received-spf:\s*(fail|softfail))/gi); } },
    { id: 'dkim', name: 'DKIM check failed', points: 10,
      why: 'DKIM is a digital signature. A failure means the message was altered or not signed by the claimed domain.',
      detect: function (c) { return scan(c, /dkim=fail/gi); } },
    { id: 'dmarc', name: 'DMARC check failed', points: 15,
      why: 'DMARC ties SPF and DKIM to the visible From address. A failure is a strong sign of spoofing.',
      detect: function (c) { return scan(c, /dmarc=fail/gi); } }
  ];

  function band(score) { return score >= 60 ? { label: 'High Risk', cls: 'high' } : score >= 30 ? { label: 'Suspicious', cls: 'mid' } : { label: 'Low Risk', cls: 'low' }; }

  function analyse(raw) {
    raw = String(raw || '');
    var ctx = prepare(raw), findings = [], total = 0;
    RULES.forEach(function (r) {
      var ev = r.detect(ctx);
      if (ev && ev.length) { findings.push({ id: r.id, name: r.name, points: r.points, why: r.why, evidence: ev }); total += r.points; }
    });
    var score = Math.min(100, total), b = band(score), ids = findings.map(function (f) { return f.id; });
    var has = function () { return [].slice.call(arguments).some(function (i) { return ids.indexOf(i) > -1; }); };
    var recs = [];
    if (b.cls !== 'low') recs.push('Do not reply, click any links or open any attachments, even to "see what happens".');
    if (has('password', 'mfa')) recs.push('Never share a password or verification code in response to a message. If you already did, change the password from the official site and report it to your IT team or provider now.');
    if (has('bank', 'payment')) recs.push('Do not pay or change any payment details. Confirm by phone using a number you already trust, not one from the email.');
    if (has('attach_exec', 'attach_unusual', 'macro')) recs.push('Leave the attachment unopened. If you think it could be genuine, ask the sender through another channel to confirm they sent it.');
    if (has('shortlink', 'ipurl', 'badurl', 'mismatch', 'harvest')) recs.push('If the message claims to be from a real organisation, go to its official website or app by typing the address yourself.');
    if (has('replyto', 'spf', 'dkim', 'dmarc')) recs.push('The sender details look unreliable. Treat the "From" name as unverified.');
    if (b.cls !== 'low') recs.push('Report it: use your email provider\'s "report phishing" option or forward it to your IT or security team, then delete it.');
    recs.push('This tool only spots warning signs. A low score is not proof of safety, so verify anything important through an official channel.');
    var summary = b.cls === 'high' ? 'Many strong warning signs. Treat this message as hostile.' : b.cls === 'mid' ? 'Some warning signs. Handle with caution and verify independently.' : findings.length ? 'Few warning signs found, but this is not a guarantee.' : 'No known warning signs found, but this is not a guarantee.';
    return { score: score, raw: total, label: b.label, cls: b.cls, summary: summary, findings: findings, recs: recs };
  }

  // ---------- Fictional demo emails (reserved fake domains, no working links) ----------
  var DEMOS = [
    { title: 'Obvious phishing', text: 'From: "PayPaI Security" <support@paypa1-secure.invalid>\nSubject: URGENT!!! Your account will be suspended\n\nDear Customer,\n\nWe noticed unauthorized activity. Your account will be suspended within 24 hours unless you act now.\nConfirm your password and verify your account here: http://203.0.113.45/paypal/login\n\nPayment of a $5 processing fee is required to restore access.\n\nPayPal Security Team' },
    { title: 'Sophisticated phishing', text: 'From: "Priya Nair, Finance" <accounts@northwind-logistics.example>\nReply-To: priya.nair@northwind-payments.invalid\nAuthentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\nSubject: Updated remittance details\n\nHi Sam,\n\nThanks for your patience on the March shipment. Ahead of this month\'s run, our bank details have changed following an audit. Please use the new account on the attached statement for the outstanding invoice and let me know once it is scheduled.\n\nKind regards,\nPriya' },
    { title: 'Fake Microsoft 365 warning', text: 'From: "Microsoft 365 Admin" <no-reply@m365-notice.invalid>\nSubject: Your password expires today\n\nHello User,\n\nYour Microsoft 365 password expires in 24 hours. To keep your mailbox, verify your account now and reply with the verification code we send you.\n\n<a href="https://secure-microsoft365-login.invalid/verify">https://login.microsoftonline.com</a>\n\nIT Support Team' },
    { title: 'Fake parcel delivery', text: 'From: FastParcel Delivery <track@fastparcel-update.invalid>\nSubject: Delivery failed\n\nDear customer,\n\nWe could not deliver your parcel. Pay a redelivery fee of N$25 immediately or it will be deleted: bit.ly/DEMO-NOT-REAL\n\nDelivery Support Team' },
    { title: 'Fake invoice / BEC', text: 'From: "Dana Whitfield (CEO)" <dana.whitfield@acme-holdings.example>\nReply-To: dana.whitfield.ceo@mail-relay.invalid\nAuthentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail\nSubject: Quick favour\n\nAre you at your desk? I am in a meeting and cannot take calls. I need you to buy gift cards for a client today. Keep this confidential and send me the codes as soon as possible.\n\nAttached is the overdue invoice: Invoice_8841.pdf.exe\n\nDana' },
    { title: 'Legitimate email', text: 'From: "Jordan Lee" <jordan.lee@example.com>\nReply-To: jordan.lee@example.com\nAuthentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\nSubject: Team meeting notes, Thursday\n\nHi team,\n\nThanks for a productive session. Notes and the agenda for next week are on the shared drive: https://www.example.com/team/agenda\n\nPlease add any topics before Wednesday.\n\nBest,\nJordan' }
  ];

  root.PhishAnalyser = { analyse: analyse, DEMOS: DEMOS, RULES: RULES };
  if (typeof module !== 'undefined' && module.exports) module.exports = root.PhishAnalyser;

  // ---------- Interface ----------
  if (typeof document === 'undefined') return;
  var $ = function (s) { return document.querySelector(s); };
  var box = $('#email');

  DEMOS.forEach(function (d) {
    var b = document.createElement('button');
    b.type = 'button'; b.textContent = d.title;
    b.addEventListener('click', function () { box.value = d.text; render(analyse(d.text)); });
    $('#demos').appendChild(b);
  });
  $('#analyse').addEventListener('click', function () {
    if (!box.value.trim()) { box.focus(); return; }
    render(analyse(box.value));
  });
  $('#clear').addEventListener('click', function () { box.value = ''; $('#result').hidden = true; $('#empty').hidden = false; box.focus(); });

  function el(tag, text, cls) { var e = document.createElement(tag); if (text) e.textContent = text; if (cls) e.className = cls; return e; }

  function render(r) {
    $('#empty').hidden = true; $('#result').hidden = false;
    var v = $('.verdict'); v.className = 'verdict ' + r.cls;
    $('#ring').style.setProperty('--p', r.score);
    $('#score').textContent = r.score;
    $('#label').textContent = r.label;
    $('#summary').textContent = r.summary;
    $('#sum').textContent = r.findings.length
      ? 'Score = ' + r.findings.map(function (f) { return f.points; }).join(' + ') + ' = ' + r.raw + (r.raw > 100 ? ' (capped at 100)' : '') + '. Bands: 0-29 Low Risk, 30-59 Suspicious, 60-100 High Risk.'
      : 'No warning-sign rules were triggered, so the score is 0.';
    var list = $('#findings'); list.textContent = '';
    if (!r.findings.length) list.appendChild(el('li', 'No warning signs detected.', 'none'));
    r.findings.forEach(function (f) {
      var li = el('li'), row = el('div', '', 'row');
      row.appendChild(el('span', f.name)); row.appendChild(el('span', '+' + f.points, 'pts'));
      li.appendChild(row); li.appendChild(el('p', f.why));
      f.evidence.forEach(function (e) { li.appendChild(el('code', e)); });
      list.appendChild(li);
    });
    var recs = $('#recs'); recs.textContent = '';
    r.recs.forEach(function (t) { recs.appendChild(el('li', t)); });
    $('#result').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
})(typeof window !== 'undefined' ? window : globalThis);
