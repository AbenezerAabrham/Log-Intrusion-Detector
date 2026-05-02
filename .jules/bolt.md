## 2025-05-15 - Redundant Object.entries() in hot loops
**Learning:** Calling `Object.entries()` inside a loop that iterates over thousands of lines causes significant overhead due to repeated array allocations. For a 100k line log, this resulted in 100k unnecessary allocations of the patterns array.
**Action:** Always hoist object property/entry access outside of high-frequency loops.

## 2025-05-15 - Array allocation overhead with .filter()
**Learning:** Using `.filter()` before a `.forEach()` or `for` loop on a large array (like log lines) creates an entirely new array in memory. This is measurable as a performance hit when processing large datasets in the browser.
**Action:** Combine filtering logic into the main processing loop using `continue` to skip unwanted elements.
