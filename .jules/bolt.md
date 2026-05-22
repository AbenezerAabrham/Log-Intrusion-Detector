## 2025-05-15 - Hoisting Regex and Single-Pass Loops in Log Analysis

**Learning:** In hot paths processing large text datasets (like log files), repeated operations like `Object.entries(PATTERNS)`, regex instantiation, and multi-pass array filtering/mapping introduce significant overhead. `Object.entries()` in particular creates a new array of entries every time it's called.

**Action:** Hoist static configuration (regexes, entries) outside the processing function. Replace functional array methods (`split().filter().forEach()`) with a single-pass `for` loop that performs filtering, extraction, and analysis in one go. This reduced processing time for 100k lines by over 50% in this application.
