// LogWatch — Log Intrusion Detector
// Author: Abenezer | MIT License | 2026
//
// Heuristic and pattern-based log analysis for identifying common
// web application and server attacks (Brute-force, SQLi, XSS, Path Traversal, etc.)

'use strict';

/* --- THREAT SIGNATURES --- */

const PATTERNS = {
  sqli: {
    regex: /(?:union\s+all\s+select|select\s+.*?\s+from|insert\s+into|drop\s+table|update\s+.*?\s+set|1=1|1'='1|waitfor\s+delay|--|\/\*)/i,
    name: 'SQL Injection',
    type: 'critical',
    score: 40,
    desc: 'Database injection payload detected (e.g., SELECT, UNION, or syntax manipulation).'
  },
  xss: {
    regex: /(?:<script>|%3Cscript|javascript:|onerror=|onload=|eval\()/i,
    name: 'Cross-Site Scripting (XSS)',
    type: 'high',
    score: 35,
    desc: 'Malicious JavaScript payload attempting to execute in the browser.'
  },
  traversal: {
    regex: /(?:\.\.\/|\.\.\\|%2e%2e%2f|\/etc\/passwd|\/etc\/shadow|c:\\windows|boot\.ini)/i,
    name: 'Directory Traversal',
    type: 'critical',
    score: 45,
    desc: 'Attempt to break out of the web root and access system files.'
  },
  admin: {
    regex: /(?:\/admin|\/wp-admin|\/phpmyadmin|\/config|\/setup|\/install\.php)/i,
    name: 'Admin Interface Access',
    type: 'medium',
    score: 15,
    desc: 'Suspicious request targeting hidden administrative or configuration panels.'
  },
  bad_ua: {
    regex: /(?:sqlmap|nikto|nmap|masscan|zgrab|curl\/|wget\/|python-requests)/i,
    name: 'Suspicious User-Agent',
    type: 'high',
    score: 25,
    desc: 'Traffic originates from a known vulnerability scanner, fuzzer, or script.'
  }
};

/* --- SAMPLE LOGS --- */
const SAMPLES = {
  brute: `192.168.1.100 - - [17/Mar/2026:10:00:01 +0000] "POST /login HTTP/1.1" 401 120 "-" "Mozilla/5.0"
192.168.1.100 - - [17/Mar/2026:10:00:03 +0000] "POST /login HTTP/1.1" 401 120 "-" "Mozilla/5.0"
192.168.1.100 - - [17/Mar/2026:10:00:05 +0000] "POST /login HTTP/1.1" 401 120 "-" "Mozilla/5.0"
192.168.1.100 - - [17/Mar/2026:10:00:06 +0000] "POST /login HTTP/1.1" 401 120 "-" "Mozilla/5.0"
192.168.1.100 - - [17/Mar/2026:10:00:08 +0000] "POST /login HTTP/1.1" 401 120 "-" "Mozilla/5.0"
10.0.0.5 - - [17/Mar/2026:10:05:00 +0000] "GET /index.html HTTP/1.1" 200 4501 "-" "Chrome/120.0"`,
  
  sqli: `172.16.0.5 - - [17/Mar/2026:14:22:10 +0000] "GET /products?id=1' OR '1'='1 HTTP/1.1" 200 8500 "-" "Mozilla/5.0"
172.16.0.5 - - [17/Mar/2026:14:22:15 +0000] "GET /products?id=1 UNION ALL SELECT user,pass FROM users-- HTTP/1.1" 200 12050 "-" "Mozilla/5.0"
172.16.0.5 - - [17/Mar/2026:14:23:01 +0000] "GET /../../../etc/passwd HTTP/1.1" 403 210 "-" "Mozilla/5.0"
10.0.0.2 - - [17/Mar/2026:14:25:00 +0000] "GET /style.css HTTP/1.1" 200 1050 "-" "Chrome"`,
  
  scan: `203.0.113.50 - - [17/Mar/2026:03:15:01 +0000] "GET /wp-login.php HTTP/1.1" 404 150 "-" "sqlmap/1.5"
203.0.113.50 - - [17/Mar/2026:03:15:02 +0000] "GET /.git/config HTTP/1.1" 404 150 "-" "sqlmap/1.5"
203.0.113.50 - - [17/Mar/2026:03:15:03 +0000] "GET /.env HTTP/1.1" 404 150 "-" "sqlmap/1.5"
203.0.113.50 - - [17/Mar/2026:03:15:04 +0000] "GET /api/v1/users HTTP/1.1" 404 150 "-" "sqlmap/1.5"
203.0.113.50 - - [17/Mar/2026:03:15:05 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 150 "-" "sqlmap/1.5"
203.0.113.50 - - [17/Mar/2026:03:15:06 +0000] "GET /backup.zip HTTP/1.1" 404 150 "-" "sqlmap/1.5"
203.0.113.50 - - [17/Mar/2026:03:15:07 +0000] "GET /server-status HTTP/1.1" 403 210 "-" "sqlmap/1.5"`,

  clean: `192.168.1.15 - - [17/Mar/2026:09:00:01 +0000] "GET / HTTP/1.1" 200 4521 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.15 - - [17/Mar/2026:09:00:02 +0000] "GET /assets/main.js HTTP/1.1" 200 1250 "http://example.com/" "Mozilla/5.0"
192.168.1.15 - - [17/Mar/2026:09:00:02 +0000] "GET /assets/style.css HTTP/1.1" 200 890 "http://example.com/" "Mozilla/5.0"
192.168.1.15 - - [17/Mar/2026:09:00:45 +0000] "POST /api/telemetry HTTP/1.1" 204 0 "http://example.com/" "Mozilla/5.0"
10.0.0.8 - - [17/Mar/2026:09:05:10 +0000] "GET /about-us HTTP/1.1" 200 3210 "-" "Chrome/120.0.0.0"
10.0.0.8 - - [17/Mar/2026:09:05:12 +0000] "GET /favicon.ico HTTP/1.1" 200 115 "-" "Chrome/120.0.0.0"`
};

// --- CORE ANALYSIS ENGINE ---

function analyzeLogs(rawText) {
  if (!rawText.trim()) {
    return { valid: false, error: 'Log input is empty. Please paste logs first.' };
  }

  // BOLT OPTIMIZATION: Avoid intermediate array creation from filtering
  const lines = rawText.split('\n');
  const events = [];
  const findingsMap = new Map();
  const ipStats = {};

  let riskTotal = 0;
  let flaggedLinesCount = 0;

  // regex to roughly extract IP and HTTP Status from common access logs
  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
  const statusRegex = /\s([2345]\d{2})\s/;

  // BOLT OPTIMIZATION: Hoist PATTERNS entries outside the loop
  const patternEntries = Object.entries(PATTERNS);
  const patternLen = patternEntries.length;

  // BOLT OPTIMIZATION: Use standard for-loop for hot path processing
  for (let i = 0, len = lines.length; i < len; i++) {
    const line = lines[i];
    if (!line.trim()) continue;

    let lineType = 'safe'; // default
    let highestLineScore = 0;
    const flaggedReasons = [];
    
    // basic extraction
    const ipMatch = line.match(ipRegex);
    const ip = ipMatch ? ipMatch[0] : 'unknown';
    const statusMatch = line.match(statusRegex);
    const status = statusMatch ? parseInt(statusMatch[1], 10) : null;

    if (!ipStats[ip]) {
      ipStats[ip] = { count: 0, 401: 0, 403: 0, 404: 0, 500: 0 };
    }
    const stats = ipStats[ip];
    stats.count++;
    if (status === 401) stats[401]++;
    else if (status === 403) stats[403]++;
    else if (status === 404) stats[404]++;
    else if (status >= 500) stats[500]++;

    // Regex Check 1: Iterating over defined patterns (SQLi, XSS, Path traversal, etc)
    for (let j = 0; j < patternLen; j++) {
      const [key, rule] = patternEntries[j];
      if (rule.regex.test(line)) {
        flaggedReasons.push(rule.name);
        
        // Ensure finding appears only once in summary
        let finding = findingsMap.get(key);
        if (!finding) {
          findingsMap.set(key, { ...rule, occurrence: 1 });
          riskTotal += rule.score; // only add score once per pattern type for overall log
        } else {
          finding.occurrence++;
        }

        // track severity
        const lineVal = rule.type === 'critical' ? 3 : rule.type === 'high' ? 2 : 1;
        if (lineVal > highestLineScore) {
          highestLineScore = lineVal;
          lineType = rule.type;
        }
      }
    }

    // Save event if flagged
    if (flaggedReasons.length > 0) {
      flaggedLinesCount++;
      events.push({
        lineNum: i + 1,
        ip,
        content: line,
        severity: lineType,
        reasons: flaggedReasons.join(', ')
      });
    }
  }

  // Heuristics 2: IP Aggregation checks
  Object.entries(ipStats).forEach(([ip, stats]) => {
    // Brute Force: 4+ Auth failures (401/403)
    const fails = stats[401] + stats[403];
    if (fails >= 4) {
      if (!findingsMap.has('brute_' + ip)) {
        findingsMap.set('brute_' + ip, {
          name: 'Authentication Brute Force',
          type: 'critical',
          score: 50,
          desc: `Multiple authentication failures (${fails}) from a single IP address (${ip}).`
        });
        riskTotal += 50;
      }
      events.push({
        lineNum: 'Agg',
        ip,
        content: `${fails} authentication failures (401/403) aggregated for ${ip}`,
        severity: 'critical',
        reasons: 'Brute Force'
      });
    }

    // Port Scan / Dir Busting: 6+ 404s
    if (stats[404] >= 6) {
      if (!findingsMap.has('scan_' + ip)) {
        findingsMap.set('scan_' + ip, {
          name: 'Directory Busting / Scanning',
          type: 'high',
          score: 30,
          desc: `Anomalous volume of 404 Not Found errors (${stats[404]}) from a single IP (${ip}). Indicates blind scanning for endpoints.`
        });
        riskTotal += 30;
      }
      events.push({
        lineNum: 'Agg',
        ip,
        content: `${stats[404]} 404 Not Found errors aggregated for ${ip}`,
        severity: 'high',
        reasons: 'Scanner Behavior'
      });
    }
  });

  // Determine overall severity
  const score = Math.min(100, Math.round(riskTotal));
  let risk;
  if (score >= 70) risk = 'CRITICAL';
  else if (score >= 50) risk = 'HIGH';
  else if (score >= 25) risk = 'MEDIUM';
  else if (score >= 5) risk = 'LOW';
  else risk = 'SAFE';

  // Format final returns
  const findings = Array.from(findingsMap.values());
  const uniqueIps = Object.keys(ipStats).length;

  return {
    valid: true,
    score,
    risk,
    events,
    findings,
    summary: {
      totalLines: lines.length,
      flaggedLines: flaggedLinesCount,
      uniqueIps
    }
  };
}


// --- UI RENDERING ---

const CIRCUMFERENCE = 2 * Math.PI * 52; // 326.73

function getRiskClass(risk) {
  return { SAFE: 'risk-safe', LOW: 'risk-low', MEDIUM: 'risk-medium', HIGH: 'risk-high', CRITICAL: 'risk-critical' }[risk];
}

function getRingColor(risk) {
  return { SAFE: '#10b981', LOW: '#22d3ee', MEDIUM: '#f59e0b', HIGH: '#f97316', CRITICAL: '#ef4444' }[risk];
}

function getVerdictText(risk) {
  return {
    SAFE: { icon: '🛡️', label: 'CLEAN', desc: 'Logs appear safe. No suspicious signatures or malicious patterns were identified.' },
    LOW: { icon: '✅', label: 'LOW RISK', desc: 'Minor anomalies detected. It might be normal background noise or scanners.' },
    MEDIUM: { icon: '⚠️', label: 'MEDIUM RISK', desc: 'Suspicious requests detected. Review the flagged events to ensure they were blocked.' },
    HIGH: { icon: '🚨', label: 'HIGH RISK', desc: 'Strong attack signatures detected. Immediate review recommended to prevent exploitation.' },
    CRITICAL: { icon: '🔴', label: 'CRITICAL', desc: 'Severe intrusion attempts identified. Compromise is possible. Investigate right away.' },
  }[risk];
}

function getRecommendation(risk) {
  const recs = {
    SAFE: {
      cls: 'rec-safe', icon: '🛡️', header: 'No Action Required',
      body: 'No obvious intrusions detected. Standard log retention and monitoring practices are sufficient.'
    },
    LOW: {
      cls: 'rec-safe', icon: '💡', header: 'Normal Background Noise',
      body: 'These alerts usually represent automated internet scanners. Ensure your external services are fully patched.'
    },
    MEDIUM: {
      cls: 'rec-warn', icon: '⚠️', header: 'Verify Block Status',
      body: 'Targeted scanning or low-level attacks seen. Check your WAF/Firewall logs to confirm these requests resulted in 403/404 errors.'
    },
    HIGH: {
      cls: 'rec-warn', icon: '🚨', header: 'Investigate Payload and Source',
      body: 'Active attack detected.<ul><li>Verify if the server responded with 200 OK to any payload.</li><li>Consider rate-limiting or IP-blocking the source.</li></ul>'
    },
    CRITICAL: {
      cls: 'rec-danger', icon: '💀', header: 'Immediate Incident Response',
      body: 'High-severity attacks (SQLi, Brute-Force, LFI).<ul><li>Check application logs to confirm if the attack succeeded.</li><li>If credentials were brute-forced successfully, force password resets and check logins.</li><li>Block attacking IPs immediately at the firewall edge.</li></ul>'
    },
  };
  return recs[risk];
}

function renderLogSummary(summary) {
  return `
    <div class="url-bd-row">
      <span class="url-bd-key">Total Lines Parsed</span>
      <span class="url-bd-part">${summary.totalLines.toLocaleString()}</span>
    </div>
    <div class="url-bd-row">
      <span class="url-bd-key">Unique IP Addresses</span>
      <span class="url-bd-part">${summary.uniqueIps.toLocaleString()}</span>
    </div>
    <div class="url-bd-row">
      <span class="url-bd-key">Flagged Events</span>
      <span class="url-bd-part" style="${summary.flaggedLines > 0 ? 'color: var(--amber-light)' : ''}">${summary.flaggedLines.toLocaleString()}</span>
    </div>
  `;
}

function renderFindings(findings) {
  if (!findings.length) {
    return `
      <div class="finding-card flag-ok">
        <div class="finding-header">
          <span class="finding-icon">✅</span>
          <span class="finding-title">No Signatures Triggered</span>
        </div>
        <div class="finding-detail">Log heuristic engine passed completely clean.</div>
      </div>
    `;
  }
  
  return findings.map((f, i) => `
    <div class="finding-card flag-${f.type === 'critical' ? 'error' : f.type === 'high' ? 'warn' : 'caution'}" style="animation-delay:${0.05 + i * 0.06}s">
      <div class="finding-header">
        <span class="finding-icon">${f.type === 'critical' ? '💥' : f.type === 'high' ? '🎯' : '🕵️'}</span>
        <span class="finding-title">${f.name}</span>
      </div>
      <div class="finding-detail">${f.desc} ${f.occurrence ? '<br><small><i>Detected ' + f.occurrence + ' time(s)</i></small>' : ''}</div>
    </div>
  `).join('');
}

function renderEventTable(events) {
  if (events.length === 0) return '';
  return events.map(ev => `
    <div class="event-row">
      <div class="event-severity ${ev.severity}" title="Severity: ${ev.severity}"></div>
      <div class="event-content">
        <div class="event-type ${ev.severity}">[${ev.lineNum}] ${ev.reasons} — IP: ${ev.ip}</div>
        <div class="event-line">${escapeHtml(ev.content)}</div>
      </div>
    </div>
  `).join('');
}

function escapeHtml(unsafe) {
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

function animateScore(targetScore, ringEl, numEl) {
  const duration = 1200;
  const start = performance.now();
  
  function step(now) {
    const t = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - t, 4);
    const current = Math.round(ease * targetScore);
    numEl.textContent = current;
    ringEl.style.strokeDashoffset = CIRCUMFERENCE - (ease * targetScore / 100) * CIRCUMFERENCE;
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function displayResults(result) {
  const panel = document.getElementById('resultsPanel');
  const riskCls = getRiskClass(result.risk);

  // Stats Summary
  document.getElementById('logSummary').innerHTML = renderLogSummary(result.summary);

  // Verdict row
  const verdictRow = panel.querySelector('.verdict-row');
  verdictRow.className = `verdict-row ${riskCls}`;

  const { icon, label, desc } = getVerdictText(result.risk);
  document.getElementById('verdictBadge').innerHTML = `${icon} ${label}`;
  document.getElementById('verdictDesc').textContent = desc;

  // Animate ring + score
  const ringFill = document.getElementById('ringFill');
  const scoreNum = document.getElementById('scoreNum');
  ringFill.style.stroke = getRingColor(result.risk);
  animateScore(result.score, ringFill, scoreNum);

  // Threat meter
  document.getElementById('threatBarFill').style.width = result.score + '%';

  // Findings cards
  document.getElementById('findingsGrid').innerHTML = renderFindings(result.findings);

  // Event table
  const tableSec = document.getElementById('eventTableSection');
  if (result.events.length > 0) {
    document.getElementById('eventTable').innerHTML = renderEventTable(result.events);
    tableSec.style.display = 'block';
  } else {
    tableSec.style.display = 'none';
  }

  // Recommendation
  const rec = getRecommendation(result.risk);
  const recBox = document.getElementById('recommendation');
  recBox.className = `recommendation-box glass ${rec.cls}`;
  recBox.innerHTML = `
    <div class="rec-header">
      <span class="rec-icon">${rec.icon}</span>
      ${rec.header}
    </div>
    <div class="rec-body">${rec.body}</div>
  `;

  // Show panel
  panel.classList.remove('hidden');
  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function showError(msg) {
  const panel = document.getElementById('resultsPanel');
  panel.innerHTML = `
    <div class="glass" style="border-radius:14px;padding:28px 24px;text-align:center;border-color:rgba(239,68,68,0.3);">
      <div style="font-size:2rem;margin-bottom:12px">❌</div>
      <div style="font-weight:700;color:#ef4444;margin-bottom:8px">Input Error</div>
      <div style="color:#64748b;font-size:0.9rem">${msg}</div>
    </div>
  `;
  panel.classList.remove('hidden');
}


// --- EVENT WIRING ---

document.addEventListener('DOMContentLoaded', () => {
  const logInput = document.getElementById('logInput');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const clearBtn = document.getElementById('clearBtn');
  const resetBtn = document.getElementById('resetBtn');
  const resultsPanel = document.getElementById('resultsPanel');

  // Input styling handling
  logInput.addEventListener('input', () => {
    clearBtn.style.display = logInput.value.length > 0 ? 'flex' : 'none';
  });

  clearBtn.addEventListener('click', () => {
    logInput.value = '';
    clearBtn.style.display = 'none';
    logInput.focus();
    resultsPanel.classList.add('hidden');
  });

  // Example Chips
  document.querySelectorAll('.example-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const type = chip.dataset.type;
      logInput.value = SAMPLES[type] || '';
      clearBtn.style.display = 'flex';
      triggerAnalysis(logInput.value);
    });
  });

  // Analyze button
  analyzeBtn.addEventListener('click', () => {
    const val = logInput.value;
    if (val.trim()) triggerAnalysis(val);
  });

  // Reset button
  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      resultsPanel.classList.add('hidden');
      logInput.value = '';
      clearBtn.style.display = 'none';
      logInput.focus();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  function triggerAnalysis(text) {
    analyzeBtn.classList.add('loading');
    analyzeBtn.disabled = true;

    // Simulate async processing
    setTimeout(() => {
      const result = analyzeLogs(text);
      analyzeBtn.classList.remove('loading');
      analyzeBtn.disabled = false;

      if (!result.valid) {
        showError(result.error);
      } else {
        displayResults(result);
      }
    }, 600);
  }

  logInput.focus();
});
