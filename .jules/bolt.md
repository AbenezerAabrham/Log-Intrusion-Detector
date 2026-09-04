## 2026-09-03 - Hoisting Regexes and Avoiding Intermediate Arrays in Log Processing
**Learning:** In hot client-side log parsing loops processing ~100k lines, re-instantiating regexes or iterating via higher-order functions (`.forEach`, `.filter`) and allocating intermediate arrays per line creates significant garbage collection overhead and execution latency.
**Action:** Hoist static regular expressions and pre-flatten pattern objects outside the analysis function; use single-pass sequential index-based `for` loops, lazy array allocations, and inline counter tracking for ~30-35% speedup.
