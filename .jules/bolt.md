## 2026-03-17 - [Optimizing Log Analysis Hot Path]
**Learning:** Hoisting static regexes and pre-calculating `Object.entries(PATTERNS)` outside the `analyzeLogs` function significantly reduces overhead in the hot path. Replacing functional array methods (`forEach`, `filter`) with standard `for` loops further improves performance by reducing function call overhead and avoiding intermediate array creation.

**Action:** Always hoist static regexes and object entries when they are used in high-frequency loops. Prefer standard `for` loops over `forEach` for performance-critical code processing large datasets.
