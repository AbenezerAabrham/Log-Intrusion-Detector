
## 2026-06-08 - [Hoisting and Loop Optimization in Log Analysis]
**Learning:** Hoisting static regexes and pre-calculating Object.entries(PATTERNS) avoids repeated overhead in high-frequency loops. Replacing functional forEach with standard for loops and caching object property lookups (like ipStats[ip]) significantly reduces execution time in Node.js/V8 environments for large data processing.
**Action:** Always look for static definitions and object-to-array conversions inside loops and move them to the outer scope. Use imperative loops for hot paths.
