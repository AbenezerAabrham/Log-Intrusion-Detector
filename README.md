# LogWatch — Automated Log Intrusion Detector 🛡️
Live Demo : https://log-intrusion-detector-iota.vercel.app/
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Status: Active](https://img.shields.io/badge/Status-Active-success.svg)]()
[![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-red.svg)]()
[![SIEM](https://img.shields.io/badge/Tool-Log_Analysis-orange.svg)]()

**LogWatch** is a next-generation, client-side, automated server log intrusion detector and threat hunting tool. Designed for SOC analysts, system administrators, and cybersecurity enthusiasts, LogWatch instantly analyzes raw server logs for malicious activities such as brute-force attacks, SQL injection (SQLi), Cross-Site Scripting (XSS), directory traversal, and more. 

> **Google Search Keywords**: Log Intrusion Detection, Automated Log Analysis, Web Server Security, Apache/Nginx Log Analyzer, Identify Server Attacks, SOC Triage Tool, Cyber Threat Hunting, Heuristic log analysis.

---

## ✨ Features

- **🚀 Instant Client-Side Analysis**: All processing happens locally in your browser. No data ever leaves your device, ensuring maximum privacy and compliance.
- **🧠 Heuristic Threat Engine**: Uses advanced pattern matching to not just find exact signatures, but anomalous patterns representing novel attack vectors.
- **🎯 Highly Accurate Threat Scoring**: Calculates a definitive Risk Score (0-100) based on severity, frequency, and correlation of suspicious events.
- **📊 SOC-Grade Verdicts**: Gives immediate, actionable feedback on the threat level (Clean, Suspicious, Critical) and provides specific remediation recommendations.
- **🔍 Granular Finding Cards**: Breaks down specifically what was found (e.g., *SSH Brute Force Detected*, *SQLi Attempt*).
- **📝 Comprehensive Event Table**: See every single flagged event in a structured tabular format for deep-dive investigations.
- **🎨 Premium Dark UI**: Features a modern, responsive, "glassmorphism" dark theme with a beautifully crafted dashboard experience.

---

## 🛠️ Installation & Setup

Because LogWatch is completely client-side, there are no dependencies to install or backend servers to spin up!

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/YourUsername/log-intrusion-detector.git
   ```
2. **Navigate to the Directory**:
   ```bash
   cd log-intrusion-detector
   ```
3. **Run the Application**:
   Simply open `index.html` in your favorite modern web browser.
   ```bash
   # On macOS
   open index.html

   # On Linux
   xdg-open index.html

   # On Windows
   start index.html
   ```

---

## 💻 How to Use

1. **Open the Tool**: Launch `index.html` in your browser.
2. **Input Logs**: Paste your raw server logs (Apache, Nginx, SSH, auth.log, etc.) directly into the text area.
3. **Scan**: Click the **Scan Logs** button.
4. **Review Results**:
   - Check the **Score Ring** and **Verdict** for an immediate high-level overview.
   - Review the **Findings Grid** for categorized attack attempts.
   - Inspect the **Flagged Events Log** for pinpointing exact log lines that triggered the alerts.
   - Follow the **Mitigation Recommendations** to secure your infrastructure.

---

## 🧠 What Does LogWatch Detect?

LogWatch comes pre-built with detection signatures and heuristics for:
- **Brute Force Attacks (SSH, FTP, Web Login)**: High failure rates from single IPs.
- **SQL Injection (SQLi)**: Payloads containing `UNION`, `SELECT`, `OR 1=1`, and encoded SQL variants.
- **Cross-Site Scripting (XSS)**: Script tags, `onerror`, and encoded alert payloads.
- **Directory Traversal**: Attempts to access `/etc/passwd`, `C:\Windows`, or `../../` patterns.
- **Command Injection**: Appended commands using `;`, `|`, or `&&`.
- **Malicious Bots & Scanners**: Nmap, Nikto, DirBuster, and unknown automated user agents.
- **Port Scans / Enumeration**: Excessive `404 Not Found` requests from a single source.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page]().

1. **Fork** the project.
2. Create your **Feature Branch** (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. **Push** to the branch (`git push origin feature/AmazingFeature`).
5. Open a **Pull Request**.

---

## 🛡️ Security

This tool does not collect telemetry, analytics, or log data. It operates 100% offline in your browser. If you find a security vulnerability within the tool itself, please report it privately.

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

> *Created with ❤️ by Abenezer. Defend your networks.*
