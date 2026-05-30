## 2026-05-30 - Log Processing Optimization
**Learning:** In the core log analysis engine (`analyzeLogs`), using functional array methods like `.forEach` and `.filter` inside loops that process hundreds of thousands of lines introduces significant overhead due to function call stack and scope creation. Additionally, repeated calls to `Object.entries(PATTERNS)` and regex literal evaluation on every line significantly slow down execution.

**Action:** Hoist static regexes and pre-calculate `Object.entries()` outside the main analysis function. Replace functional iteration with standard `for` loops in hot paths to achieve ~30% faster processing on large datasets. Use manual counters instead of intermediate array filtering for summary statistics.
