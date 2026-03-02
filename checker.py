# =============================================================================
# checker.py — Part 2: Basic Security Checks
# =============================================================================
#
# WHAT THIS FILE DOES:
#   Takes the list of endpoints from the crawler and runs 4 security checks
#   on each one. Outputs a structured JSON report of findings.

import requests
import logging
import json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)



class SecurityChecker:

    def __init__(self, base_url):
        """
        Sets up the checker with the target base URL.
        """
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"
        })

        # ---- CHECK 1 CONFIG: Sensitive path keywords ----
        # If any of these words appear in a URL, it's worth flagging.
        self.sensitive_keywords = {
            # keyword       : severity level
            "admin"         : "high",
            "config"        : "high",
            ".env"          : "critical",
            ".git"          : "critical",
            "backup"        : "high",
            "debug"         : "medium",
            "secret"        : "high",
            "password"      : "high",
            "token"         : "medium",
            "api-key"       : "high",
            "internal"      : "medium",
            "private"       : "medium",
            "swagger"       : "medium",   # API documentation — shouldn't be public
            "actuator"      : "high",     # Spring Boot internal metrics endpoint
        }

        # ---- CHECK 3 CONFIG: Security headers we expect to see ----
        # These are HTTP response headers that protect against common attacks.
        self.required_headers = {
            "X-Frame-Options": {
                "severity": "medium",
                "detail": "Missing X-Frame-Options — site may be vulnerable to clickjacking attacks"
            },
            "Content-Security-Policy": {
                "severity": "medium",
                "detail": "Missing Content-Security-Policy — no protection against XSS injection"
            },
            "X-Content-Type-Options": {
                "severity": "low",
                "detail": "Missing X-Content-Type-Options — browser may mis-interpret response type"
            },
            "Strict-Transport-Security": {
                "severity": "medium",
                "detail": "Missing HSTS header — connection may be downgraded to HTTP"
            },
        }

        # ---- CHECK 4 CONFIG: Info disclosure patterns ----
        # These regex patterns look for things that shouldn't be in a response body.
        self.disclosure_patterns = [
            (r"(?i)express[\s/][\d.]+",       "Server framework version exposed (Express.js)"),
            (r"(?i)node\.js[\s/v][\d.]+",     "Runtime version exposed (Node.js)"),
            (r"at\s+\w+\s+\(.+\.js:\d+:\d+\)","Stack trace exposed in response"),
            (r"(?i)sql syntax",                "SQL error message exposed"),
            (r"(?i)syntax error",              "Syntax error exposed in response"),
            (r"/home/\w+/",                    "Internal Unix file path exposed"),
            (r"C:\\\\Users\\\\",               "Internal Windows file path exposed"),
            (r"(?i)password=\w+",              "Password visible in response body"),
            (r"(?i)secret[_-]?key\s*[:=]",    "Secret key visible in response body"),
        ]

    # =========================================================================
    def check_all(self, endpoints):
        """
        Runs all 4 security checks on every endpoint.

        Parameters:
            endpoints (list): List of path strings like ["/api/Products", "/rest/login"]

        Returns:
            list: A list of result dictionaries, one per endpoint.
        """
        results = []

        for i, endpoint in enumerate(endpoints):
            logger.info(f"[{i+1}/{len(endpoints)}] Checking: {endpoint}")

            # Build the full URL from the base + path
            # e.g. "http://localhost:3000" + "/api/Products" → "http://localhost:3000/api/Products"
            full_url = self.base_url + endpoint

            # This dict will hold all findings for this endpoint
            endpoint_result = {
                "endpoint": endpoint,
                "full_url": full_url,
                "findings": []
            }

            # --- Run Check 1: Sensitive path keywords ---
            findings_1 = self._check_sensitive_path(endpoint)
            endpoint_result["findings"].extend(findings_1)
            # .extend() adds all items from one list into another list

            # --- Fetch the actual page (needed for checks 2, 3, 4) ---
            response = self._safe_get(full_url)

            if response is not None:
                # --- Run Check 2: Dangerous HTTP methods ---
                findings_2 = self._check_http_methods(full_url)
                endpoint_result["findings"].extend(findings_2)

                # --- Run Check 3: Missing security headers ---
                findings_3 = self._check_missing_headers(response)
                endpoint_result["findings"].extend(findings_3)

                # --- Run Check 4: Information disclosure ---
                findings_4 = self._check_info_disclosure(response)
                endpoint_result["findings"].extend(findings_4)

            # Only include endpoints that have at least one finding
            # (endpoints with no findings are clean — no need to report them)
            if endpoint_result["findings"]:
                results.append(endpoint_result)

        logger.info(f"Security checks complete. {len(results)} endpoints with findings.")
        return results

    # =========================================================================
    # CHECK 1: SENSITIVE PATH KEYWORDS
    # =========================================================================
    def _check_sensitive_path(self, endpoint):
        """
        Checks if the URL path contains keywords associated with sensitive areas.

        This is the simplest check — just string matching.
        No HTTP request needed, just look at the URL itself.
        """
        findings = []

        # .lower() converts the string to lowercase so "Admin" matches "admin"
        endpoint_lower = endpoint.lower()

        # Loop through our keyword dictionary
        # .items() gives us both the key AND value at the same time
        for keyword, severity in self.sensitive_keywords.items():
            if keyword in endpoint_lower:
                # Create a finding dictionary and add it to our list
                findings.append({
                    "type": "sensitive_path",
                    "severity": severity,
                    "detail": f"URL contains sensitive keyword: '{keyword}'"
                })

        return findings

    # =========================================================================
    # CHECK 2: DANGEROUS HTTP METHODS
    # =========================================================================
    def _check_http_methods(self, url):
        """
        Sends an OPTIONS request to see what HTTP methods the server allows.

        HTTP METHODS QUICK LESSON:
        ┌─────────┬──────────────────────────────────────────────────────────┐
        │ Method  │ Purpose                                                  │
        ├─────────┼──────────────────────────────────────────────────────────┤
        │ GET     │ Read data (safe)                                         │
        │ POST    │ Create data (normal for APIs)                            │
        │ PUT     │ Update data (normal for APIs)                            │
        │ DELETE  │ Delete data (normal for APIs)                            │
        │ OPTIONS │ Ask server "what methods do you allow here?" (safe)      │
        │ TRACE   │ Diagnostic — can be exploited for XST attacks (bad!)    │
        │ PUT     │ Can allow arbitrary file upload if misconfigured (risky) │
        └─────────┴──────────────────────────────────────────────────────────┘

        The server responds with an "Allow" header listing what it supports.
        """
        findings = []

        # Methods that are concerning if allowed unnecessarily
        dangerous_methods = ["TRACE", "CONNECT", "PATCH"]

        try:
            # Send an OPTIONS request (we only need to see the headers, not the body)
            response = self.session.options(url, timeout=5)

            # The "Allow" header looks like: "GET, POST, PUT, DELETE, OPTIONS"
            allow_header = response.headers.get("Allow", "")

            if allow_header:
                # Split the header into a list of methods
                allowed_methods = [m.strip() for m in allow_header.split(",")]
                # This is a "list comprehension" — a compact way to build a list.
                # It means: for each item m in allow_header.split(","), strip whitespace.

                for method in dangerous_methods:
                    if method in allowed_methods:
                        findings.append({
                            "type": "dangerous_http_method",
                            "severity": "medium",
                            "detail": f"Potentially dangerous HTTP method allowed: {method}"
                        })

        except requests.RequestException:
            pass  # If OPTIONS fails, just skip this check

        return findings

    # =========================================================================
    # CHECK 3: MISSING SECURITY HEADERS
    # =========================================================================
    def _check_missing_headers(self, response):
        """
        Checks if important security headers are present in the HTTP response.

        HTTP HEADERS QUICK LESSON:
        When a server sends back a webpage, it also sends "headers" — metadata
        about the response. Security headers tell the browser how to behave safely.

        Example response headers:
            HTTP/1.1 200 OK
            Content-Type: text/html
            X-Frame-Options: DENY          ← "Don't let this be shown in an iframe"
            Content-Security-Policy: ...   ← "Only load scripts from trusted sources"
        """
        findings = []

        # response.headers is a dictionary of all headers in the response
        for header_name, config in self.required_headers.items():
            if header_name not in response.headers:
                findings.append({
                    "type": "missing_header",
                    "severity": config["severity"],
                    "detail": config["detail"]
                })

        return findings

    # =========================================================================
    # CHECK 4: INFORMATION DISCLOSURE
    # =========================================================================
    def _check_info_disclosure(self, response):
        """
        Scans the response BODY for things that shouldn't be publicly visible —
        like version numbers, error messages, or internal file paths.

        Uses regex (re module) to find patterns in text.
        """
        import re
        findings = []

        # Only scan if the response has a text body
        # (don't try to scan image/binary files)
        content_type = response.headers.get("Content-Type", "")
        if not any(t in content_type for t in ["text", "json", "javascript"]):
            return findings

        body = response.text  # The raw text content of the response

        for pattern, description in self.disclosure_patterns:
            # re.search() looks for the pattern ANYWHERE in the text.
            # Returns a Match object if found, or None if not found.
            if re.search(pattern, body):
                findings.append({
                    "type": "information_disclosure",
                    "severity": "medium",
                    "detail": description
                })

        return findings

    # =========================================================================
    # HELPER: SAFE GET REQUEST
    # =========================================================================
    def _safe_get(self, url):
        """
        Makes a GET request and returns the response, or None if it fails.
        This is a "helper method" — it handles the try/except so we don't
        have to repeat it in every check method.
        """
        try:
            response = self.session.get(url, timeout=5)
            return response
        except requests.RequestException as e:
            logger.warning(f"GET request failed for {url}: {e}")
            return None

    # =========================================================================
    # HELPER: SUMMARY STATS
    # =========================================================================
    def get_summary_stats(self, results):
        """
        Takes the results list and computes summary statistics.
        Useful for the AI analysis step.
        """
        total_findings = sum(len(r["findings"]) for r in results)
        # sum() adds up numbers. len() counts items in a list.
        # This is a "generator expression" — like a list comprehension but more memory-efficient.

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for result in results:
            for finding in result["findings"]:
                severity = finding.get("severity", "low")
                if severity in severity_counts:
                    severity_counts[severity] += 1

        return {
            "endpoints_with_findings": len(results),
            "total_findings": total_findings,
            "by_severity": severity_counts
        }


# =============================================================================
# RUN THIS FILE DIRECTLY (for testing)
# =============================================================================
if __name__ == "__main__":
    # Load endpoints from the file that crawler.py saved
    try:
        with open("endpoints.json", "r") as f:
            data = json.load(f)
        endpoints = data["endpoints_found"]
        print(f"Loaded {len(endpoints)} endpoints from endpoints.json")
    except FileNotFoundError:
        # If endpoints.json doesn't exist yet, use a small test set
        print("endpoints.json not found — using sample endpoints for testing")
        endpoints = [
            "/rest/admin/application-configuration",
            "/api/Products",
            "/rest/user/login",
            "/.git",
        ]

    # Run the checks
    checker = SecurityChecker(base_url="http://localhost:3000")
    results = checker.check_all(endpoints)
    stats = checker.get_summary_stats(results)

    # Build the full output
    output = {
        "summary": stats,
        "results": results
    }

    print(json.dumps(output, indent=2))

    # Save to file (for use in Part 3)
    with open("security_findings.json", "w") as f:
        json.dump(output, f, indent=2)
    print("\n✅ Saved to security_findings.json")
