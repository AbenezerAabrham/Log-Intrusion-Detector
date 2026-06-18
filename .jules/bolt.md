## 2025-05-15 - [Optimize log analysis engine]
**Learning:** Standard `for` loops and hoisting static regexes/constants significantly outperform `.forEach` and inline declarations in hot paths for log processing. Avoiding intermediate array operations like `.filter().length` in favor of manual counters also provides a measurable boost.
**Action:** Always look for hoisting opportunities and use standard `for` loops in performance-critical data processing functions.
