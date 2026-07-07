## 2026-06-25 - Caching Object.entries in Hot Loops
**Learning:** Calling `Object.entries(PATTERNS).forEach` inside a loop that iterates over hundreds of thousands of log lines causes significant overhead due to repeated array allocations and iterator creation.
**Action:** Hoist `Object.entries(obj)` to a constant outside the loop and use a standard `for` loop to iterate over the cached entries. This, combined with other micro-optimizations (hoisting regexes, avoiding intermediate `.filter()` calls), resulted in a ~42% performance improvement.
