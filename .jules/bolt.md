## 2026-03-20 - Hoisting Regex and Loop Refactoring in Log Parsing

**Learning:** Re-creating regex objects and iterating over object entries (`Object.entries()`) inside a loop that processes tens of thousands of log lines causes significant overhead. Additionally, using functional array methods like `.split().filter().forEach()` creates multiple intermediate arrays, increasing memory pressure and garbage collection frequency. Standard `for` loops in V8 remain significantly faster for hot paths involving large datasets.

**Action:** Always hoist static regexes and loop-invariant calculations (like `Object.entries(PATTERNS)`) outside of hot loops. Prefer standard `for` loops and single-pass iteration (using `continue` for filtering) when processing large raw text inputs to minimize allocations and maximize throughput.
