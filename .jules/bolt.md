## 2026-06-28 - [Log Analysis Loop Optimization]
**Learning:** Hoisting static regexes and pattern entries outside of high-frequency loops, combined with replacing `.forEach` with standard `for` loops, significantly reduces GC pressure and function call overhead in log processing tasks.
**Action:** Always check for redundant object/array allocations and iterative method overhead in tight loops processing large datasets.

## 2026-06-28 - [Manual Counter Tracking]
**Learning:** Tracking counts manually during a main loop traversal is more efficient than performing a subsequent `.filter().length` on the resulting array, especially for large datasets.
**Action:** Integrate counters into primary data processing passes to avoid extra iterations.
