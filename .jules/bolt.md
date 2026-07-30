# Bolt's Journal - Log Intrusion Detector

## 2026-07-30 - Initial Setup
**Learning:** Found no existing journal or test files. The project is a pure frontend app with no `package.json` or standard test framework.
**Action:** Create a Node.js-based benchmark script to profile, optimize, and verify our performance improvements.

## 2026-07-30 - High Performance Log Parsing
**Learning:** Calling `Object.entries(PATTERNS)` inside high-frequency loops (like the log line processing loop) generates significant garbage collection pressure due to millions of array allocations. Similarly, `.filter(...)` on splits, `.forEach(...)` callback layers, and redundant `parseInt` calls add overhead that accumulates drastically over hundreds of thousands of lines.
**Action:** Hoisted `IP_REGEX`, `STATUS_REGEX`, and flat `PATTERN_ENTRIES` to the module/global scope. Replaced all higher-order methods with sequential index-based `for` loops. Skipped empty lines in a single-pass loop (maintaining correct UI line references via the raw index `i + 1`). Cached nested lookups for `ipStats[ip]`, lazy-initialized arrays only when matched, used fast unary `+` instead of `parseInt`, and avoided intermediate array filtering for summary metrics. This yielded a measurably faster execution path (33.4% faster, ~207.56ms down from ~311.89ms for 100,000 log lines).
