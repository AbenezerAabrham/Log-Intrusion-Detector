# Bolt's Journal - Log Intrusion Detector

## 2026-07-23 - Initial Analysis of Log Intrusion Detector Performance
**Learning:** Found that `analyzeLogs` in `detector.js` performs several expensive operations inside a high-frequency loop for every log line:
1. `Object.entries(PATTERNS)` is called on every line iteration, which creates a new array of key-value pairs and causes high garbage collection overhead.
2. `lines.forEach(...)` and `.filter(...)` create intermediate arrays and incur callback invocation overhead.
3. `ipRegex` and `statusRegex` are declared inside the function.
4. `parseInt` is used on status code matches inside the loop.
5. `flaggedReasons` array is allocated for every single line even if no patterns match.

**Action:** Hoist patterns and regexes, replace `forEach` and `.filter` with standard index-based `for` loops, cache lookups, lazy-allocate arrays, and use unary `+` instead of `parseInt` to significantly boost log analysis speed.
