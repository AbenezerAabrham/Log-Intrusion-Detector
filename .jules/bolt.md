## 2026-06-15 - Hot Path Optimization in Log Analysis
**Learning:** In high-volume text processing (100k+ lines), the overhead of `.forEach()`, `.filter()`, and repeated `Object.entries()` inside loops becomes a significant bottleneck due to closure creation and redundant object traversals. Hoisting regexes and constants, and using standard `for` loops, provides a measurable 25-30% speedup.
**Action:** Always identify hot paths (like `analyzeLogs`) and apply low-level loop optimizations (hoisting, standard for-loops, property caching) when processing large datasets.

## 2026-06-15 - Stable Benchmarking in Node.js
**Learning:** Benchmarking tight loops in Node.js is susceptible to V8 JIT optimization phases. Initial runs are often slower, and performance can fluctuate until the code is fully optimized by the engine.
**Action:** Always include a warmup phase and run multiple iterations (5-10+) to establish a stable average when measuring micro-optimizations.
