## 2026-06-25 - Optimize Log Analysis Engine
**Learning:** Using high-order functions like .forEach and .filter inside hot loops (like processing 100k+ log lines) adds significant overhead in V8 due to callback creation and intermediate array allocations. Hoisting static regexes and object entries also avoids repeated work.
**Action:** Always prefer standard for loops and hoisted constants for performance-critical loops.
