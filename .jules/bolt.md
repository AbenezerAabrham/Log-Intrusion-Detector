## 2026-08-06 - [Single-Pass Splitting & Custom Index Tracking]
**Learning:** Removing intermediate `.filter()` arrays during text splitting improves performance by eliminating GC pressure, but can break functional parity of line numbers. By keeping a separate `nonEmptyIndex` counter while doing a single-pass loop on unfiltered lines, we can maintain 100% exact functional parity with original line numbers without sacrificing performance.
**Action:** In future text/log parsing optimizations, use a custom tracker inside a single-pass sequential loop instead of pre-filtering raw lines.
