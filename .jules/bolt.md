## 2026-03-17 - Optimized analyzeLogs hot path
**Learning:** Functional array methods like `.filter()` and `.forEach()` introduce significant overhead in hot loops processing large datasets (e.g. 50k+ log lines). Creating intermediate arrays and repeated object access (e.g. `Object.entries()`) inside loops further degrades performance.
**Action:** Use standard `for` loops, hoist static regexes and constants outside the hot path, and maintain manual counters to avoid multiple passes over the data.
