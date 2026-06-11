# Bolt's Performance Journal

## 2026-06-11 - Hoisting regex and using for loops in log processing
**Learning:** In the `analyzeLogs` function, repeatedly creating regexes (implicitly or explicitly) and using `forEach` on large arrays (100k+ lines) creates significant overhead. Hoisting static regexes and using standard `for` loops reduces execution time by over 50%.
**Action:** Always hoist static regexes and prefer standard `for` loops over `forEach` for hot paths involving large data sets.
