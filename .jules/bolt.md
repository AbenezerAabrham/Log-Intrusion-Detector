## 2026-04-26 - [Optimizing log analysis hot path]
**Learning:** In hot paths processing large datasets (like 100k+ log lines), avoiding intermediate array creation (via `.filter()`) and hoisting object property access (via `Object.entries()`) significantly reduces execution time. Replacing functional array methods with standard `for` loops also provides a measurable boost in performance.
**Action:** Always check for `.filter().forEach()` chains in data-processing loops and consider merging them into a single `for` loop with early `continue` for empty/invalid data.
