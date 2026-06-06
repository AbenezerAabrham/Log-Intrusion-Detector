## 2026-06-06 - Optimizing Core Log Analysis Loop

**Learning:** Hoisting static regexes and object entries out of a high-frequency loop (like `analyzeLogs` processing thousands of log lines) significantly reduces allocation overhead and execution time in V8. Additionally, replacing functional array methods (`forEach`, `Object.entries`) with imperative `for` loops and manually counting results instead of using `.filter().length` provides a measurable performance boost.

**Action:** Always hoist static definitions (Regex, entries) outside of processing loops. Prefer imperative loops over functional ones for hot paths involving large datasets. Use manual counters instead of redundant array passes for summary statistics.
