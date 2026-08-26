## 2026-08-26 - Single-Pass Log Traversal & Regex Hoisting Optimization
**Learning:** In client-side JS log parsing engines, `rawText.split('\n').filter(...)` creates huge intermediate array allocations. Combined with `Object.entries(PATTERNS)` inside a `.forEach()` loop per log line, thousands of redundant objects and array allocations are made per scan.
**Action:** Hoist regexes and pattern entries to module scope, use a single-pass index-based `for` loop over split lines skipping blank lines inline, lazy-allocate `flaggedReasons`, cache object lookups, and track summary counts inline.
