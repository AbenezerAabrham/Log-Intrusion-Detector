# Bolt's Performance Journal

## 2026-06-25 - Initializing Bolt Journal
**Learning:** Establishing a performance-focused mindset for the LogWatch codebase.
**Action:** Always measure before and after optimizations using `benchmark.js`.

## 2026-06-25 - Optimizing analyzeLogs with Hoisting and Standard Loops
**Learning:** Hoisting regexes and pre-calculating `Object.entries(PATTERNS)` combined with replacing `.forEach` with standard `for` loops and avoiding intermediate array filtering significantly reduces execution time for large logs.
**Result:** Reduced execution time for 100,000 log lines from ~688ms to ~463ms (approx. 32% speedup).
**Action:** Always check for repeated object property enumeration or regex allocation in hot loops.
