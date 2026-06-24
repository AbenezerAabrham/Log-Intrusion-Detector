## 2026-06-24 - [Hoisting and Loop Optimization in Log Analysis]
**Learning:** Replacing functional iterators (`forEach`, `filter`) and `Object.entries()` with standard `for` loops in the core log analysis path significantly reduces overhead. Hoisting static regexes and pattern entries outside the hot path also provides a measurable boost. In this codebase, these changes reduced processing time for 100k log lines from ~374ms to ~280ms (~25% speedup).
**Action:** Always prefer standard `for` loops and hoist static definitions when optimizing high-frequency processing logic like log parsing.
