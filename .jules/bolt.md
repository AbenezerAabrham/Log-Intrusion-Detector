## 2026-05-18 - [Hoisting and Loop Optimization]
**Learning:** Hoisting static computations like `Object.entries(PATTERNS)` and regex definitions outside of high-frequency loops significantly reduces overhead. Using standard `for` loops instead of `forEach` or `filter` avoids closure creation and intermediate array allocations, which is critical for processing large log files.
**Action:** Always look for static computations inside loops that can be hoisted, and prefer standard `for` loops for performance-critical data processing paths.
