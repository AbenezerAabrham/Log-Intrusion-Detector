## 2026-06-30 - Log Processing Optimization
**Learning:** Hoisting static regexes and pre-calculating `Object.entries()` outside of high-frequency loops significantly reduces GC pressure and execution time. Caching object property lookups (like `ipStats[ip]`) and replacing `Array.prototype.forEach` with standard `for` loops provides measurable gains in hot paths.
**Action:** Always check for repeated object-to-array conversions (like `Object.entries`) or regex creations inside loops that process large datasets.
