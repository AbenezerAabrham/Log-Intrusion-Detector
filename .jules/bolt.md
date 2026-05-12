## 2026-05-12 - [Optimizing Log Analysis Performance]
**Learning:** Hoisting constants and regexes outside of hot paths (like a log analysis loop) and replacing multi-pass array methods (.filter, .forEach) with a single-pass standard 'for' loop significantly reduces execution time by avoiding redundant allocations and function call overhead.

**Action:** Always check for opportunities to hoist static computations and refactor functional array chains into single-pass loops in performance-critical sections.
