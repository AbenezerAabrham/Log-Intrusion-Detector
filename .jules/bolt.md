## 2026-06-30 - Hoisting static constants and avoiding intermediate arrays in log analysis
**Learning:** In the `analyzeLogs` engine, repeatedly calling `Object.entries(PATTERNS)` and defining regexes inside the loop caused significant overhead. Additionally, using `.split('\n').filter(...)` creates intermediate arrays that increase memory pressure and GC cycles.
**Action:** Hoist all static regexes and pre-calculate `Object.entries()` outside the main processing loop. Use standard `for` loops and manual counters to avoid unnecessary array allocations.
