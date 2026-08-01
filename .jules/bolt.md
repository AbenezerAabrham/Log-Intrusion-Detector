# Bolt Performance Journal

## 2026-08-01 - Initializing Performance Journal
**Learning:** Initialized Bolt performance journal to keep track of performance improvements and findings in this codebase.
**Action:** Document bottlenecks and keep a clean performance history.

## 2026-08-01 - Optimizing Log Intrusion Detection Performance in detector.js
**Learning:** Found that invoking `Object.entries(PATTERNS)` inside a loop over 100,000 log lines causes massive memory and CPU overhead. By hoisting static regular expressions outside the loop, pre-mapping `PATTERNS` to a flat, cacheable `PATTERN_ENTRIES` array, and avoiding array generation from split-filter preprocessing, we can dramatically increase throughput. Using index-based sequential `for` loops rather than high-overhead `.forEach` loops delivers massive JIT compilation gains.
**Action:** Pre-calculate object-to-array transformations outside high-frequency loops, lazy-allocate temporary array indicators, and utilize simple sequential `for` loops for processing lines to maximize performance.
