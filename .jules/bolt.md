## 2026-03-20 - [Optimized log analysis performance]
**Learning:** Hoisting static regexes (IP_REGEX, STATUS_REGEX) and PATTERN_ENTRIES, and replacing functional methods like 'forEach' and 'filter' with standard 'for' loops in the critical log analysis path significantly reduces execution time. For 100k log lines, the analysis time dropped from ~645ms to ~468ms (approx. 27% improvement).
**Action:** Always prefer imperative 'for' loops and hoisting of static definitions in performance-critical data processing paths.
