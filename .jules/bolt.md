## 2026-06-22 - [Optimized analyzeLogs in detector.js]
**Learning:** Hoisting static regexes and constants, replacing `.forEach()` with standard `for` loops, and using manual counters instead of `.filter().length` provides a significant performance boost (~35%) in tight log-processing loops.
**Action:** Always identify static values and regexes inside loops and move them to a higher scope. Use standard `for` loops for large data sets to avoid function call overhead.
