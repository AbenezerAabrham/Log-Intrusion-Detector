## 2025-05-14 - [analyzeLogs optimization]
**Learning:** Hoisting static regexes and pattern entries, combined with replacing functional array methods (forEach, filter) with standard for-loops, provides significant performance gains in hot paths involving large datasets.
**Action:** Always look for hoisting opportunities and use standard for-loops for performance-critical data processing.
