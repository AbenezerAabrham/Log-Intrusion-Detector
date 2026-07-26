## 2026-07-26 - [LogWatch Heuristic Core Optimizer]
**Learning:** Hoisting high frequency lookups, using pre-constructed PATTERN_ENTRIES arrays, and processing raw lines with single-pass sequential index-based standard loops avoids excessive memory/GC pressure and gives a massive execution time speedup in client-side log parsers.
**Action:** When working on log scanners or parser engines, avoid nested loop iterations, array methods (like `.forEach()`, `.filter()`), and dynamic `Object.entries()` inside inner hot-paths. Standard `for` loops combined with lazy object allocation are much faster.
