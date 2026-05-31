## 2025-05-15 - [Log Analysis Optimization]
**Learning:** Hoisting `Object.entries(PATTERNS)` and replacing `forEach` with standard `for` loops in the core log processing loop significantly reduces overhead, especially with large datasets (100k+ lines). Functional array methods like `filter` or `forEach` introduce callback overhead that accumulates in hot paths.
**Action:** Always hoist static object/array entries and prefer standard `for` loops for performance-critical processing of large arrays.
