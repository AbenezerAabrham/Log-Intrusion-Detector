## 2026-03-24 - Optimizing Log Analysis Performance
**Learning:** Functional array methods like `.forEach()` and repeated calls to `Object.entries()` inside hot loops significantly impact performance when processing large datasets (e.g., 100k+ log lines). Hoisting static regexes and pre-calculating entries outside the loop, along with using standard `for` loops, can yield measurable speedups.
**Action:** Prefer standard `for` loops and hoist static definitions when processing large arrays or performing intensive pattern matching in hot paths.
