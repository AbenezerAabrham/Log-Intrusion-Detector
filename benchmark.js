// Performance Benchmark for LogWatch
const fs = require('fs');
const vm = require('vm');

// Mock document for loading browser script
globalThis.document = {
  addEventListener: () => {}
};

// Load code helper
function loadEngine(filename) {
  const code = fs.readFileSync(filename, 'utf8');
  const context = {
    document: globalThis.document,
    console: console,
    Math: Math,
    Map: Map,
    Array: Array,
    Object: Object,
    RegExp: RegExp,
    parseInt: parseInt,
    performance: performance
  };
  vm.createContext(context);
  vm.runInContext(code, context);
  return context.analyzeLogs;
}

// Generate large test logs (100,000 lines)
function generateLogs(count) {
  const lineTemplates = [
    '192.168.1.15 - - [17/Mar/2026:09:00:01 +0000] "GET / HTTP/1.1" 200 4521 "-" "Mozilla/5.0"',
    '172.16.0.5 - - [17/Mar/2026:14:22:15 +0000] "GET /products?id=1 UNION ALL SELECT user,pass FROM users-- HTTP/1.1" 200 12050 "-" "Mozilla/5.0"',
    '192.168.1.100 - - [17/Mar/2026:10:00:01 +0000] "POST /login HTTP/1.1" 401 120 "-" "Mozilla/5.0"',
    '10.0.0.8 - - [17/Mar/2026:09:05:10 +0000] "GET /about-us HTTP/1.1" 200 3210 "-" "Chrome/120.0.0.0"',
    '203.0.113.50 - - [17/Mar/2026:03:15:02 +0000] "GET /.git/config HTTP/1.1" 404 150 "-" "sqlmap/1.5"',
    '172.16.0.5 - - [17/Mar/2026:14:23:01 +0000] "GET /../../../etc/passwd HTTP/1.1" 403 210 "-" "Mozilla/5.0"',
    '192.168.1.15 - - [17/Mar/2026:09:00:02 +0000] "GET /assets/style.css HTTP/1.1" 200 890 "http://example.com/" "Mozilla/5.0"',
    '192.168.1.100 - - [17/Mar/2026:10:00:03 +0000] "POST /login HTTP/1.1" 401 120 "-" "Mozilla/5.0"',
    '10.0.0.8 - - [17/Mar/2026:09:05:12 +0000] "GET /favicon.ico HTTP/1.1" 200 115 "-" "Chrome/120.0.0.0"',
    '192.168.1.100 - - [17/Mar/2026:10:00:05 +0000] "POST /login HTTP/1.1" 401 120 "-" "Mozilla/5.0"'
  ];

  let logs = '';
  for (let i = 0; i < count; i++) {
    logs += lineTemplates[i % lineTemplates.length] + '\n';
  }
  return logs;
}

const logCount = 100000;
console.log(`Generating ${logCount} log lines for benchmark...`);
const testLogs = generateLogs(logCount);

// Measure a function
function runBenchmark(analyzeFn, label) {
  console.log(`\n--- Benchmarking: ${label} ---`);

  // Warmup phase (important for JIT optimization)
  console.log('Warming up JIT compiler (5 runs)...');
  for (let i = 0; i < 5; i++) {
    analyzeFn(testLogs);
  }

  // Active benchmarking phase
  const iterations = 10;
  console.log(`Running ${iterations} iterations...`);
  const start = performance.now();

  let lastResult;
  for (let i = 0; i < iterations; i++) {
    lastResult = analyzeFn(testLogs);
  }

  const totalTime = performance.now() - start;
  const avgTime = totalTime / iterations;

  console.log(`Result: ${label} average execution time: ${avgTime.toFixed(2)}ms`);

  if (lastResult && lastResult.summary) {
    console.log(`Summary stats from last run:`);
    console.log(`- Total lines: ${lastResult.summary.totalLines}`);
    console.log(`- Flagged lines: ${lastResult.summary.flaggedLines}`);
    console.log(`- Unique IPs: ${lastResult.summary.uniqueIps}`);
    console.log(`- Overall Score: ${lastResult.score} (${lastResult.risk})`);
    console.log(`- Total Events: ${lastResult.events.length}`);
    console.log(`- Total Findings: ${lastResult.findings.length}`);
  }

  return { avgTime, lastResult };
}

// Main execution
const origAnalyze = loadEngine('./detector_orig.js');
const origRes = runBenchmark(origAnalyze, 'Original Engine');

let optAnalyze;
try {
  optAnalyze = loadEngine('./detector.js');
} catch (e) {
  console.log('\n(detector.js not optimized or contains error yet)');
}

if (optAnalyze) {
  const optRes = runBenchmark(optAnalyze, 'Optimized Engine');
  const speedup = ((origRes.avgTime - optRes.avgTime) / origRes.avgTime) * 100;
  console.log(`\n🚀 Speedup: ${speedup.toFixed(2)}% faster!`);

  // Verify correctness (functional parity)
  const origOut = JSON.stringify(origRes.lastResult);
  const optOut = JSON.stringify(optRes.lastResult);
  if (origOut === optOut) {
    console.log('✅ PASS: Functional parity verified! The optimized engine produced identical results.');
  } else {
    console.log('❌ FAIL: Functional parity failed!');
    // Detailed checks
    if (origRes.lastResult.score !== optRes.lastResult.score) {
      console.log(`Mismatch in score: Orig=${origRes.lastResult.score}, Opt=${optRes.lastResult.score}`);
    }
    if (origRes.lastResult.risk !== optRes.lastResult.risk) {
      console.log(`Mismatch in risk: Orig=${origRes.lastResult.risk}, Opt=${optRes.lastResult.risk}`);
    }
    if (origRes.lastResult.events.length !== optRes.lastResult.events.length) {
      console.log(`Mismatch in events length: Orig=${origRes.lastResult.events.length}, Opt=${optRes.lastResult.events.length}`);
    }
    if (origRes.lastResult.findings.length !== optRes.lastResult.findings.length) {
      console.log(`Mismatch in findings length: Orig=${origRes.lastResult.findings.length}, Opt=${optRes.lastResult.findings.length}`);
    }
    if (JSON.stringify(origRes.lastResult.summary) !== JSON.stringify(optRes.lastResult.summary)) {
      console.log(`Mismatch in summary: Orig=${JSON.stringify(origRes.lastResult.summary)}, Opt=${JSON.stringify(optRes.lastResult.summary)}`);
    }
  }
}
