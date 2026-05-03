## 2026-05-03 - Hoisting and Loop Optimization in `analyzeLogs`
**Learning:** In hot paths processing hundreds of thousands of lines, `Object.entries().forEach()` and intermediate array filters significantly impact performance due to object allocation and garbage collection pressure.
**Action:** Always hoist object iterations and prefer single-pass `for` loops for large dataset processing.
