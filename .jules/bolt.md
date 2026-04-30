## 2025-05-15 - Single-pass Log Processing Optimization

**Learning:** In client-side log analysis, using functional array methods like `.filter().forEach()` on large datasets (hundreds of thousands of lines) creates significant overhead due to intermediate array allocation and repeated callback execution. Pre-calculating/hoisting static object entries (like `Object.entries(PATTERNS)`) outside the main loop further reduces iteration costs.

**Action:** Prefer standard `for` loops and inline condition checks (like skipping empty lines) to process large datasets in a single pass. Hoist metadata lookups and pre-calculate severity values to keep the "hot path" as lean as possible.
