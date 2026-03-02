# =============================================================================
# crawler.py — Part 1: Endpoint Discovery
# =============================================================================
#   Visits a website, finds all links (in HTML and JavaScript files),
#   and returns a list of unique URL paths (called "endpoints").

import requests                          
from bs4 import BeautifulSoup            
from urllib.parse import urljoin, urlparse 
import re                               
import logging                          


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


# --- THE CRAWLER CLASS -------------------------------------------------------

class Crawler:

    def __init__(self, base_url, max_depth=2):
        """
        __init__ is the "constructor" — it runs when you create a Crawler object.
        It sets up all the initial data the crawler needs.

        Parameters:
            base_url  (str): The website to start crawling from.
            max_depth (int): How many "levels" deep to follow links.
                             depth=0 → only the start page
                             depth=1 → start page + pages it links to
                             depth=2 → one more level beyond that
        """

        # self.something = value  stores data ON the object so other methods can use it.
        self.base_url = base_url.rstrip("/")  # Remove trailing slash for consistency

    
        self.base_domain = urlparse(base_url).netloc  # e.g. "localhost:3000"

        self.max_depth = max_depth

    
        self.visited_urls = set()    # URLs we've already crawled
        self.found_endpoints = set() # Unique endpoint paths discovered

        # A requests.Session() is like a browser session — it remembers cookies,
        # which helps us stay "logged in" across multiple requests.
        self.session = requests.Session()

        # Set a User-Agent header so the server thinks we're a real browser.
        # Some servers block requests that don't look like a browser.
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"
        })

        # These are keywords that appear in interesting/sensitive paths.
        self.sensitive_keywords = [
            "admin", "config", "backup", "debug", ".git",
            ".env", "secret", "password", "token", "api-key"
        ]

    # -------------------------------------------------------------------------
    def crawl(self):
        """
        The main entry point. Call this to start crawling.
        Returns a list of all unique endpoints found.
        """
        logger.info(f"Starting crawl of {self.base_url} (max depth: {self.max_depth})")

        # Start crawling from the base URL at depth 0
        self._crawl_url(self.base_url, depth=0)

        logger.info(f"Crawl complete. Found {len(self.found_endpoints)} unique endpoints.")

        # Convert set to a sorted list for clean output
        return sorted(list(self.found_endpoints))

    # -------------------------------------------------------------------------
    def _crawl_url(self, url, depth):
        """
        Visits a single URL, extracts links from it, then visits those links.
        The underscore prefix (_) is a Python convention meaning "internal method —
        don't call this directly from outside the class."

        This function calls itself indirectly (through the loop below), which
        creates a chain of crawling that goes deeper and deeper until max_depth.

        Parameters:
            url   (str): The URL to visit right now
            depth (int): How deep we currently are (starts at 0)
        """

        # STOP CONDITIONS — don't crawl if:
        if depth > self.max_depth:
            return  # Gone too deep
        if url in self.visited_urls:
            return  # Already been here
        if not url.startswith(self.base_url):
            return  # It's an external link (e.g. google.com) — skip it

        # Mark this URL as visited BEFORE making the request.
        # This prevents infinite loops (Page A links to Page B links back to Page A).
        self.visited_urls.add(url)

        # Extract just the path from the URL and store it as an endpoint.
        # e.g. "http://localhost:3000/rest/login" → "/rest/login"
        path = urlparse(url).path
        if path:
            self.found_endpoints.add(path)

        logger.info(f"[Depth {depth}] Crawling: {url}")

        # --- MAKE THE HTTP REQUEST -------------------------------------------
        # try/except catches errors so one broken page doesn't crash everything.
        try:
            response = self.session.get(url, timeout=5)
            # timeout=5 means: if the server doesn't respond in 5 seconds, give up.

        except requests.RequestException as e:
            # RequestException covers all request errors (connection refused, timeout, etc.)
            logger.warning(f"Failed to fetch {url}: {e}")
            return  # Skip this URL and move on

        # --- EXTRACT LINKS FROM THE PAGE -----------------------------------
        content_type = response.headers.get("Content-Type", "")
        # Content-Type tells us what kind of file the server returned.
        # "text/html" → a webpage
        # "application/javascript" → a JS file

        if "html" in content_type:
            # Parse HTML and find links
            new_urls = self._extract_links_from_html(response.text, url)
            # Also look for API endpoints hidden in JavaScript
            new_urls.update(self._extract_endpoints_from_js(response.text))

        elif "javascript" in content_type:
            # If it's a JS file, scan it for API endpoint patterns
            new_urls = self._extract_endpoints_from_js(response.text)

        else:
            new_urls = set()

        # --- RECURSE: Visit each newly found URL ----------------------------
        for new_url in new_urls:
            self._crawl_url(new_url, depth=depth + 1)
            # depth + 1 tracks how deep we're going

    # -------------------------------------------------------------------------
    def _extract_links_from_html(self, html_text, current_url):
        """
        Uses BeautifulSoup to parse HTML and find all links.
        Returns a set of absolute URLs.

        Parameters:
            html_text   (str): The raw HTML content of a page
            current_url (str): The URL of the page (needed to resolve relative links)
        """
        found = set()

        # BeautifulSoup parses the HTML into a tree we can search.
        # "html.parser" is Python's built-in HTML parser (no extra install needed).
        soup = BeautifulSoup(html_text, "html.parser")

        # --- Find all <a href="..."> links ---
        # soup.find_all("a") returns every <a> tag in the page.
        for tag in soup.find_all("a", href=True):
            # href=True means "only <a> tags that HAVE an href attribute"
            href = tag["href"]  # Get the value of the href attribute

            # urljoin converts relative URLs to absolute ones.
            # e.g. urljoin("http://localhost:3000/page", "/api/login")
            #   → "http://localhost:3000/api/login"
            # e.g. urljoin("http://localhost:3000/page", "about")
            #   → "http://localhost:3000/about"
            absolute_url = urljoin(current_url, href)

            # Only keep URLs that belong to our target site
            if urlparse(absolute_url).netloc == self.base_domain:
                # Remove query strings and fragments for cleaner endpoints
                # e.g. "http://localhost:3000/page?id=1#section" → "http://localhost:3000/page"
                clean_url = absolute_url.split("?")[0].split("#")[0]
                found.add(clean_url)

        # --- Find all <script src="..."> tags (JavaScript files) ---
        for tag in soup.find_all("script", src=True):
            src = tag["src"]
            absolute_url = urljoin(current_url, src)
            if urlparse(absolute_url).netloc == self.base_domain:
                found.add(absolute_url)

        # --- Find all <link href="..."> and <img src="..."> tags ---
        for tag in soup.find_all(["link", "img", "form"], href=True):
            href = tag.get("href") or tag.get("src") or tag.get("action")
            if href:
                absolute_url = urljoin(current_url, href)
                if urlparse(absolute_url).netloc == self.base_domain:
                    found.add(absolute_url)

        return found

    # -------------------------------------------------------------------------
    def _extract_endpoints_from_js(self, js_text):
        """
        Scans JavaScript source code for API endpoint patterns using regex.

        JUICE SHOP IS A "SINGLE PAGE APP" (SPA):
        This means most of the page is built by JavaScript. The real API
        endpoints (like /rest/user/login, /api/Products) are defined in the
        JavaScript files, not in HTML. So we MUST scan JS files to find them.

        REGEX (Regular Expressions):
        A regex is a pattern for finding text. Think of it like a very powerful
        "Ctrl+F" that can match flexible patterns.

        Examples:
          r"/api/\w+" matches: /api/Products, /api/Users, /api/Challenges, etc.
          \w+ means "one or more word characters (letters, digits, underscore)"

        Parameters:
            js_text (str): The raw JavaScript code to search through
        """
        found = set()

        # These are regex patterns for common API endpoint formats.
        # The r"..." prefix means "raw string" — backslashes are treated literally.
        patterns = [
            r'["\'](/(?:api|rest|v\d+)/[^"\'?\s]{2,})["\']',
            # Matches: "/api/Products", "/rest/user/login", "/v2/something"
            # Breakdown:
            #   ["'] → starts with a quote (single or double)
            #   (    → start of "capture group" — what we want to extract
            #   /    → literal slash
            #   (?:api|rest|v\d+) → "api" OR "rest" OR "v" followed by digits
            #   /    → another slash
            #   [^"'?\s]{2,} → 2+ characters that are NOT quotes, ?, or whitespace
            #   )    → end of capture group
            #   ["'] → ends with a quote

            r'["\'](/[a-zA-Z][a-zA-Z0-9/_-]{3,})["\']',
            # Matches longer paths like "/administration", "/score-board"
            # More general — catches paths that don't follow /api/ or /rest/ pattern

            r'\.get\(["\']([^"\']+)["\']',
            # Matches: .get("/some/endpoint") in Angular/React HTTP calls

            r'\.post\(["\']([^"\']+)["\']',
            # Matches: .post("/some/endpoint")

            r'\.put\(["\']([^"\']+)["\']',
            # Matches: .put("/some/endpoint")

            r'\.delete\(["\']([^"\']+)["\']',
            # Matches: .delete("/some/endpoint")
        ]

        for pattern in patterns:
            # re.findall() returns a list of all matches in the text
            matches = re.findall(pattern, js_text)
            for match in matches:
                # Only keep paths that look like real endpoints (start with /)
                if match.startswith("/") and len(match) > 1:
                    # Filter out obvious non-endpoints (image files, etc.)
                    skip_extensions = [".png", ".jpg", ".gif", ".css", ".ico", ".svg", ".woff"]
                    if not any(match.endswith(ext) for ext in skip_extensions):
                        self.found_endpoints.add(match)  # Store just the path
                        found.add(self.base_url + match)  # Return the full URL

        return found


# =============================================================================
# RUNNING THIS FILE DIRECTLY
# =============================================================================

if __name__ == "__main__":
    import json

    # Create a Crawler object targeting Juice Shop
    crawler = Crawler(base_url="http://localhost:3000", max_depth=2)

    # Start the crawl and get all discovered endpoints
    endpoints = crawler.crawl()

    # Build the output in the format the assignment asks for
    output = {
        "base_url": "http://localhost:3000",
        "endpoints_found": endpoints,
        "total_count": len(endpoints)
    }

    # json.dumps() converts a Python dict to a nicely formatted JSON string
    # indent=2 adds indentation so it's human-readable
    print(json.dumps(output, indent=2))

    # Also save it to a file
    with open("endpoints.json", "w") as f:
        json.dump(output, f, indent=2)
    print("\n✅ Saved to endpoints.json")
