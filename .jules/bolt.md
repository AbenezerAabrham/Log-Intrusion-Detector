## 2025-05-15 - [Hot Path Loop Optimization]
**Learning:** Hoisting static regexes and constants (like `PATTERN_ENTRIES`) and replacing `forEach` or `filter` with standard `for` loops in "hot paths" (log line processing) provides a significant performance boost (~33% in this case). Caching object property lookups (e.g., `ipStats[ip]`) inside tight loops also reduces overhead.
**Action:** Always prefer standard `for` loops and hoisted constants for data-heavy processing tasks in client-side applications.
