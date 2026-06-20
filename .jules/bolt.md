## 2026-06-20 - [Optimize analyzeLogs performance]
**Learning:** In hot loops processing large datasets (like log analysis), function call overhead from `.forEach()` and repeated object creation via `Object.entries()` significantly impact performance. Hoisting static regexes and constants, and using standard `for` loops, can yield substantial speedups.
**Action:** Always prefer standard `for` loops and hoist static definitions (regex, object entries) out of hot paths.
