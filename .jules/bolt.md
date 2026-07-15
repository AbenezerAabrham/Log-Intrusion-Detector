## 2026-07-15 - [Hoisting and Loop Optimization in Log Analysis]
**Learning:** Calling `Object.entries()` inside a high-frequency loop (like log line processing) creates massive GC pressure and unnecessary allocations. Replacing `forEach`/`filter` with standard `for` loops and manually tracking results further reduces overhead.
**Action:** Always hoist object property/entry access outside of tight loops. Prefer standard `for` loops for large data processing.
