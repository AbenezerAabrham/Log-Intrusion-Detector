## 2026-03-24 - [Optimizing heavy log processing loop]
**Learning:** In hot loops processing large datasets (100k+ lines), the overhead of functional array methods (`split().filter().forEach()`) and redundant Map lookups (`has()` followed by `get()`) can account for a significant portion of execution time. Hoisting static regexes and object entries also avoids repeated initialization costs.
**Action:** Use standard `for` loops and a single pass for both filtering and processing. Minimize Map/Object lookups by caching results. Hoist all static metadata outside the processing function.
