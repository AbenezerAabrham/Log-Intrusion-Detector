## 2026-07-18 - Optimized Log Analysis Loop
**Learning:** In highly repetitive loops, such as parsing hundreds of thousands of server log lines:
1. Creating intermediate arrays via `.filter(...)` or `.forEach(...)` inside loops causes severe garbage collection overhead.
2. Generating Regex match structures and re-parsing keys via `Object.entries(PATTERNS)` on every iteration is extremely slow. Pre-mapping patterns into flat objects and hoisting static regexes saves massive execution time.
3. Allocating empty helper arrays (like `flaggedReasons = []`) upfront for every single log line is wasteful if most lines are clean; lazy array allocation on the first match significantly reduces memory pressure.
**Action:** Always prefer standard loop index iteration over `.forEach`, avoid object spreads or `Object.entries()` inside frequent loops, and lazy-initialize structures only when they are actually needed.
