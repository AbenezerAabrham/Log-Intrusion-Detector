## 2026-07-02 - [Optimized log analysis loop performance]
**Learning:** Hoisting static regexes and pattern entries outside of a high-frequency loop, and replacing `.forEach` with standard `for` loops, significantly reduces overhead. Manually tracking aggregate metrics during the main loop also avoids extra passes over the data.
**Action:** Always hoist static regexes and entry/key conversions outside of loops. Prefer `for` loops over `.forEach` in performance-critical paths.
