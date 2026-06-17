## 2026-03-17 - [Log Analysis Optimization]
**Learning:** Significant performance gains can be achieved in log processing paths by hoisting static regexes and constants (like `Object.entries(PATTERNS)`) out of loops and replacing `forEach` with standard `for` loops.
**Action:** Always check for redundant object/array creations and non-essential iterations in high-frequency loops. Use manual counters instead of `.filter().length` on large arrays.
