# Bolt's Performance Journal

## 2025-05-15 - [Optimization of Log Analysis Loop]
**Learning:** Hoisting static regexes and pre-computing `Object.entries()` outside of high-frequency loops (like processing 100k+ log lines) significantly reduces execution time and GC pressure. Standard `for` loops also outperform `forEach` in these hot paths in V8.
**Action:** Always check for object conversions and regex definitions inside loops; move them to the highest possible scope. Use standard `for` loops for performance-critical iteration.
