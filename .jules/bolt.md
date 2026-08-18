# Bolt's Journal

## 2026-08-16 - Hot-path Log Parsing Optimization in `analyzeLogs`
**Learning:** In client-side log parsing loops processing tens of thousands of log lines, avoiding object allocations (`Object.entries`, `filter`, empty `flaggedReasons` arrays) and using flat index-based `for` loops with pre-hoisted regexes significantly reduces execution time and garbage collection pauses.
**Action:** Always pre-flatten static pattern tables, hoist regexes outside loop/function scopes, and lazy-initialize per-line data structures when analyzing raw text data.
