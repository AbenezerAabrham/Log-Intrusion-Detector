## 2026-03-17 - Hoisting and Loop Optimization in Log Analysis
**Learning:** In hot paths processing large amounts of text (like log files), hoisting static regexes and constants out of the processing function and replacing `.forEach` with standard `for` loops yields significant performance gains. Caching object property lookups inside loops also reduces overhead.
**Action:** Always check for static definitions inside frequently called functions or loops and move them out. Prefer standard `for` loops over `.forEach` for high-performance iteration in Node.js/V8.
