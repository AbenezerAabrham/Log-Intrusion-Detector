## 2026-05-06 - Log Analysis Loop Optimization
**Learning:** Standard `for` loops and single-pass processing significantly outperform functional array methods (`.forEach`, `.filter`) when processing large datasets (>50k lines) in a browser/Node environment. Hoisting static regular expressions and object entries outside the analysis function avoids redundant re-calculation and compilation overhead during high-frequency execution.
**Action:** Always prefer standard loops and hoisted constants for performance-critical data processing paths involving large arrays or repetitive lookups.
