# Bolt's Performance Journal

## 2026-03-17 - Optimizing Log Analysis Core
**Learning:** Hoisting static regexes and pre-calculating object entries significantly reduces overhead in hot loops. Replacing functional array methods (`forEach`, `filter`) with standard `for` loops and caching object property lookups in local variables further improves execution speed by reducing function call overhead and property access cost. Additionally, consolidating `Map.has()` and `Map.get()` into a single `Map.get()` and checking for `undefined` halves the number of lookups for existing keys.
**Action:** Always hoist constants used in loops, prefer standard `for` loops for performance-critical paths, and minimize Map/Object lookups by caching results in local variables.
