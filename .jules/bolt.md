## 2026-03-17 - Hoisting and Loop Optimization in Log Analysis

**Learning:** Hoisting frequently used regular expressions and object entries (Object.entries(PATTERNS)) outside of the main analysis function, combined with replacing functional array methods (forEach) with standard for loops, significantly reduces overhead when processing large datasets (e.g., 100k log lines).

**Action:** Always hoist static regexes and pre-calculate object entries when they are used within high-frequency loops. Prefer standard 'for' loops over '.forEach()' in performance-critical code paths.
