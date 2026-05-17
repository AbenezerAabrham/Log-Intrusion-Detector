## 2025-05-15 - Hot Path Optimization in Log Processing
**Learning:** Functional array methods like `.filter().forEach()` and repeated `Object.entries()` calls in a hot loop (processing 100k+ log lines) introduce significant overhead due to intermediate array allocations and redundant computations.
**Action:** Hoist static regular expressions and pre-calculate object entries outside the main processing function. Replace functional chains with single-pass `for` loops and manual counters to minimize allocations and improve execution speed.
