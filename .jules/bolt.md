# Bolt Performance Journal

This journal contains critical performance learnings, surprising results, rejected changes, and codebase-specific performance patterns/anti-patterns.

## 2026-06-25 - Hoisting Regex and Refactoring forEach to standard For Loop
**Learning:** Hoisting frequently matched regular expressions and pre-converting objects into iteration-friendly entries (`Object.entries(PATTERNS)`) outside hot functions, combined with replacing `.forEach` loops with standard `for` loops, dramatically reduces execution times. Pre-filtering lines with `split('\n').filter(...)` creates intermediate garbage arrays; keeping the unfiltered split and doing manual line validation inside a single-pass `for` loop provides a major speed boost and reduces garbage collection overhead.
**Action:** Always hoist static regex, pre-convert PATTERNS using `Object.entries` outside loop constructs, replace standard JS array loops with index-based `for` loops, and avoid creating intermediate arrays during text parsing operations.
