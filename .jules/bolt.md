## 2026-03-20 - Optimize log analysis hot path
**Learning:** In performance-critical functions like log parsing, functional array methods (split, filter, forEach) can create significant memory overhead due to intermediate array allocations. Additionally, re-calculating `Object.entries()` or re-defining Regex literals inside a loop that runs thousands of times creates unnecessary garbage collection pressure and CPU overhead.
**Action:** Always hoist constants, pre-calculate object entries, and use single-pass standard `for` loops for processing large datasets in hot paths.
