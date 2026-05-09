## 2025-05-09 - Optimized analyzeLogs in detector.js
**Learning:** Standard `for` loops significantly outperform `forEach` and `Object.entries()` in hot paths when processing large datasets (e.g., hundreds of thousands of log lines). Hoisting static regexes and pre-calculating object entries avoids redundant work in every iteration.
**Action:** Always hoist static definitions (regex, object entries) out of loops. Use standard `for` loops instead of functional array methods in performance-critical sections.
