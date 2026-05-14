# Bolt's Performance Journal

## 2025-05-15 - Optimizing `analyzeLogs` in `detector.js`
**Learning:** Functional array methods like `.filter()` and `.forEach()` in hot paths (line-by-line log processing) introduce significant overhead due to intermediate array allocations and function call overhead. Hoisting static regexes and object entries outside the function further reduces per-execution costs.
**Action:** Always prefer standard `for` loops and single-pass data processing for high-volume data analysis. Hoist constants that don't depend on function arguments.
