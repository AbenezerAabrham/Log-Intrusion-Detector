
## 2026-05-20 - Hoisting Regexes and standard For-Loops for Log Processing
**Learning:** Re-creating regex objects and calculating object entries (Object.entries) inside a high-frequency loop (every log line) significantly impacts performance. Standard 'for' loops consistently outperform functional array methods like '.forEach' in hot paths involving tens of thousands of iterations.
**Action:** Always hoist static regexes and pre-calculate object entries outside of processing loops. Prefer standard 'for' loops for heavy data processing.
