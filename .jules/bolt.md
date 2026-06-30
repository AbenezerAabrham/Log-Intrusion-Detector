## 2026-06-30 - [Optimize log analysis engine]
**Learning:** Hoisting static regexes and pattern entries, and replacing `.forEach` with standard `for` loops significantly reduces GC pressure and execution time in hot log-processing paths.
**Action:** Always hoist static object transformations and regexes outside of loops or high-frequency functions. Use standard `for` loops for performance-critical iterations in V8.
