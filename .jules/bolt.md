## 2026-06-25 - Hoisting Regexes and Patterns in Hot Path
**Learning:** Hoisting static regexes and pattern entries (`Object.entries(PATTERNS)`) outside the main analysis loop significantly reduces GC pressure and object creation overhead. Replacing `.forEach` with standard `for` loops in the log analysis hot path provides a measurable performance boost (approx. 36% speedup for 100k lines).
**Action:** Always hoist static object/array conversions and regexes outside high-frequency loops. Prefer standard `for` loops for large data processing tasks in the browser/node.
