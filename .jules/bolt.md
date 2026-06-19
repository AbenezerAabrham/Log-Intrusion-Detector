## 2025-05-14 - [Optimize analyzeLogs with hoisting and efficient loops]
**Learning:** In hot functions like `analyzeLogs` that process large arrays (logs), the overhead of creating regexes and calling `Object.entries()` on every invocation adds up. Furthermore, standard `for` loops in V8 often outperform `forEach` for large datasets due to less closure overhead.
**Action:** Hoist static regexes and constants outside processing functions. Use standard `for` loops for large log processing paths. Cache object property lookups in local variables when accessed multiple times in a loop.
