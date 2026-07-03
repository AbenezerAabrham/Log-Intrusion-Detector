## 2026-07-03 - Optimize log analysis with single-pass processing and hoisting
**Learning:** Chaining array methods like `.split().filter().forEach()` on large log inputs creates multiple intermediate arrays and increases garbage collection pressure. Hoisting regexes and pattern entries outside the loop prevents redundant re-computation.
**Action:** Use a single `for` loop to process raw text line-by-line, skipping empty lines manually, and hoist static regex/data structures outside the analysis function or loop.
