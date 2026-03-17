# LogWatch 🕵️‍♂️ (Automated Log Intrusion Detector)

*A browser-based, instant log analyzer for spotting server attacks. No servers to spin up, no data leaves your browser.*

## Why does this exist?
If you've ever stared at raw server logs (like an Nginx access log or an `auth.log`), you know it's a nightmare. Servers generate massive amounts of noise, and trying to spot a hacker poking around inside thousands of lines of normal web traffic is like finding a needle in a haystack. 

SOC (Security Operations Center) teams deal with this daily. They use automated tools to flag suspicious behavior. **LogWatch** is a lightweight, frontend-only version of those tools. It gives you instant, visual threat intel just by pasting your logs.

## What it actually does
LogWatch scans raw text logs and uses pattern matching and time-window heuristics to catch the bad guys. It flags things like:

- **Brute-Force Attacks:** Someone trying to guess passwords from the same IP, resulting in multiple 401/403 errors.
- **Directory Busting / Port Scans:** Script kiddies blindly fishing for hidden `/admin` pages or `.env` files, resulting in a spike of 404 errors.
- **SQL Injections (SQLi):** Database manipulation payloads embedded in URLs (like `' OR 1=1`).
- **Path Traversal:** Attempts to break out of the web directory to read system files (like `../../../etc/passwd`).
- **Cross-Site Scripting (XSS):** Malicious JavaScript payloads attempting to execute in the browser.
- **Suspicious User-Agents:** Traffic coming from known hacking tools or vulnerability scanners (like `sqlmap`, `nikto`, or `masscan`).

## How to use it
It's just an HTML file! 

1. Open `index.html` in your favorite browser.
2. Paste your raw server access logs into the text area.
3. Click "Scan Logs" and watch the engine parse the noise into a clean, actionable threat report. 
4. Don't have any logs on hand? Click the built-in sample chips at the top to see how it handles simulated SSH brute-force attacks or SQL injections.

## The Tech Stack
- **100% Client-Side:** Built heavily with plain HTML, modern CSS, and vanilla JavaScript mapping logic. 
- **Privacy First:** Since it's entirely frontend logic, your sensitive server logs are processed locally in your DOM. Absolutely zero data is sent to a backend API or saved anywhere.
- **Design:** Features a modern, dark-mode glassmorphism aesthetic because security tools don't have to look like they were built in 1998.
