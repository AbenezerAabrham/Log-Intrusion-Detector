## 2024-06-04 - [Hoisting & Loop Optimization in Log Processing]
**Learning:** For performance-critical log analysis, hoisting static regexes and using standard `for` loops instead of functional array methods (`forEach`, `filter`) significantly reduces overhead. Hoisting `Object.entries(PATTERNS)` outside the loop is particularly effective as it avoids repeated object-to-array conversions.
**Action:** Always identify hot paths in data processing and apply hoisting and standard loop structures.

## 2024-06-04 - [Single-Pass Processing]
**Learning:** Combining multiple operations (splitting, filtering, counting) into a single pass through the data avoids creating unnecessary intermediate arrays and reduces execution time.
**Action:** Minimize the number of times data is iterated and avoid chaining array methods on large datasets.
