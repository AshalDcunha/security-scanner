# What I Would Improve With More Time

**Current tool:** A working security scanner covering endpoint discovery, basic checks, and AI analysis — built in Python with `requests`, `BeautifulSoup`, and OpenRouter.

---

## Top Improvements

**1. Async Crawling (Biggest Impact)**  
The crawler currently processes one URL at a time, waiting for each response before moving to the next. Using `asyncio` + `httpx`, all requests could run concurrently — reducing crawl time from minutes to seconds for large sites. This is the single change that would most improve usability.

**2. Real Browser Rendering**  
Juice Shop is an Angular SPA: most endpoints are constructed dynamically by JavaScript at runtime, not hardcoded in source files. Our regex approach catches many of them, but misses any endpoint built from variables or computed paths. Using Playwright (headless Chrome) would execute the actual JavaScript and capture every real network request the app makes — far more complete than static analysis.

**3. Authentication-Aware Testing**  
Currently all requests are unauthenticated. A meaningful security assessment needs to compare what's accessible before and after login — some endpoints may be incorrectly accessible to unauthenticated users (a classic broken access control bug). Adding a login step and re-running checks with session cookies would surface these issues.

**4. Smarter Endpoint Deduplication**  
`/api/Products/1` and `/api/Products/42` are the same endpoint with different IDs. The current tool reports them separately, inflating the findings count. Normalizing parameterized paths (e.g., `/api/Products/{id}`) would produce cleaner, more actionable output.

**5. SARIF Export**  
Security findings exported in SARIF format integrate directly into GitHub's Code Scanning dashboard and other developer tools — making this usable in real CI/CD pipelines, not just as a standalone script.

**Word count: ~270**
