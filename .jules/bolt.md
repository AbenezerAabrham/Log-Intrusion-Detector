# Bolt's Performance Journal

This journal tracks critical performance learnings, bottlenecks, and optimization observations for LogWatch.

## 2026-07-24 - Initial Setup
**Learning:** Found that the core analysis engine `analyzeLogs` in `detector.js` defines regular expressions inside the function, splits logs into a pre-filtered array causing intermediate allocations, and uses slow iterator methods like `forEach` and `Object.entries` inside high-frequency loops.
**Action:** Hoist Regex/pattern constants, convert loops to standard `for` loops, optimize array allocation, and avoid intermediate arrays to dramatically speed up log analysis.
