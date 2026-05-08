## 2026-03-17 - [Optimized analyzeLogs hot path]
**Learning:** Hoisting static regexes and pre-calculating `Object.entries(PATTERNS)` outside the main loop provides a massive performance boost (nearly 2x) in hot loops processing large datasets (200k+ log lines). Standard `for` loops are also noticeably faster than `.forEach()` in this context.
**Action:** Always hoist static regexes and object entries outside of high-frequency loops. Prefer standard `for` loops for heavy data processing.
