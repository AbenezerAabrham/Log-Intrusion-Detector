## 2026-03-17 - [analyzeLogs Optimization]
**Learning:** Hoisting static regexes and pre-calculating constant object entries outside of high-frequency loops, combined with using standard 'for' loops instead of 'forEach', significantly reduces execution time in log analysis. Also, tracking summary metrics in-line avoids redundant array operations later.
**Action:** Always hoist constants and use standard loops for performance-critical processing paths in JS.
