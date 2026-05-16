## 2025-05-15 - [Optimization of analyzeLogs]
**Learning:** Hoisting static regex and pre-calculating object entries (`Object.entries(PATTERNS)`) outside the main processing loop significantly reduces overhead during large log analysis. Replacing functional array methods like `.forEach()` and `.filter()` with standard `for` loops and single-pass logic avoids intermediate array creation and reduces function call overhead, leading to measurable speedups.
**Action:** Always look for opportunities to hoist constants and refactor multi-pass array operations into single-pass loops in hot paths.
