## 2026-06-12 - Hoisting and Loop Optimization in Hot Paths
**Learning:** In log analysis where the same patterns and regexes are applied to thousands of lines, hoisting regex definitions and pre-calculating Object.entries() outside the loop significantly reduces overhead. Standard 'for' loops are also measurably faster than 'forEach' for large datasets in V8.
**Action:** Always check if objects iterated in hot loops can be pre-calculated or if regexes can be hoisted. Use standard 'for' loops when performance on large arrays is critical.
