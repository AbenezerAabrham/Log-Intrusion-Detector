## 2025-05-15 - [Log Analysis Loop Optimization]
**Learning:** In client-side log analysis, using `.forEach()` and `.filter()` over large arrays (100k+ lines) introduces significant overhead due to callback execution and intermediate array creation. Hoisting regexes and using traditional `for` loops with manual counter tracking significantly improves performance.
**Action:** Always prefer traditional `for` loops and hoist static regexes/entries outside of high-frequency analysis loops.
