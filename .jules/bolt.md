## 2026-09-05 - Log Engine Hot Loops & Allocation Overhead
**Learning:** In client-side log parsers, calling `Object.entries(PATTERNS)` inside per-line callbacks creates tens of thousands of throwaway arrays. Pre-flattening entries and using index-based `for` loops with lazy array initialization cuts runtime drastically without altering threat scoring.
**Action:** Always pre-flatten static pattern maps and hoist regular expressions outside analysis engines.
