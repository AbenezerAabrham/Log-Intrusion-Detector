## 2026-03-24 - [Optimizing Hot Loop in Log Analysis]
**Learning:** Hoisting `Object.entries(PATTERNS)` and static regexes outside of the main processing loop, combined with replacing `forEach` with standard `for` loops, significantly reduces allocation overhead and execution time. Caching `Map.get()` results avoids redundant `.has()` lookups.
**Action:** Always check for repeated object/entry lookups inside high-frequency loops and prefer standard `for` loops over functional array methods in performance-critical paths.
