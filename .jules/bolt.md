# Bolt's Performance Journal — LogWatch

## 2026-07-20 - Hoisting and Standard Loop Optimizations in Log Parsing
**Learning:**
In high-frequency log parsing scenarios, executing `Object.entries(PATTERNS)` or creating intermediate arrays (via `.filter(...)` or `.forEach(...)` callbacks) inside loops causes significant garbage collection overhead and slows down processing. Hoisting static regular expressions and converting pattern objects to flat arrays outside the hot path reduces overhead. Standard index-based `for` loops outperform callback-based iteration (`.forEach`) and array allocations. Lazy-initializing intermediate arrays like `flaggedReasons` and converting string parsing (`parseInt`) to unary prefix operators (`+`) yields further performance improvements.
**Action:**
- Hoist regular expressions (`ipRegex`, `statusRegex`) and pattern collections (`PATTERN_ENTRIES`) out of high-frequency loops.
- Use standard, index-based `for` loops instead of `.forEach` or `.filter`.
- Caching lookups of nested object properties (like `ipStats[ip]`) avoids repeated object lookups.
- Avoid pre-filtering arrays when splitting lines, and instead handle empty/whitespace lines gracefully inside the main loop while keeping accurate line indexes for the UI.
