# Bolt's Journal

## 2026-08-04 - [LogWatch Intrusion Detector Optimization]
**Learning:** Hoisting static regular expressions and converting Object.entries of patterns into a static constant PATTERN_ENTRIES outside of the function eliminates substantial GC pressure and recreation overhead. Using sequential index-based `for` loops instead of `forEach` and avoiding intermediate `filter` array allocations can lead to massive speedups.
**Action:** Hoist constants, avoid inline `Object.entries()`, utilize native `for` loops, and lazy-allocate structures.
