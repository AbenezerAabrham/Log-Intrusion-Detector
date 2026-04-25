## 2026-03-17 - [Object.entries Overhead in Hot Loops]
**Learning:** Calling `Object.entries()` inside a loop that iterates over thousands of log lines creates a massive performance bottleneck due to repeated array allocations and garbage collection pressure. Replacing `forEach` and `filter` with standard `for` loops also yielded significant speedups for large datasets.
**Action:** Always hoist object-to-array conversions (keys, values, entries) outside of high-frequency loops. Prefer `for` loops over functional array methods in performance-critical paths.
