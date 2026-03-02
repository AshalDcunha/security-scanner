# =============================================================================
# ai_analysis.py — Part 3: AI-Powered Analysis via OpenRouter
# =============================================================================
#
# WHAT THIS FILE DOES:
#   Takes the security findings from Part 2 and sends them to an LLM
#   (Large Language Model) via the OpenRouter API to get a human-readable
#   security report with prioritized recommendations.

import requests
import json
import os
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)



class AIAnalyzer:

    def __init__(self, api_key=None):
        """
        Sets up the AI analyzer.

        Parameters:
            api_key (str): Your OpenRouter API key.
                           If not provided, reads from environment variable.
        """
        # Use provided key, or fall back to environment variable
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY")

        if not self.api_key:
            raise ValueError(
                "No API key found. Set OPENROUTER_API_KEY environment variable "
                "or pass api_key= when creating AIAnalyzer."
            )

        # OpenRouter API endpoint (the URL we send requests to)
        self.api_url = "https://openrouter.ai/api/v1/chat/completions"

        # The AI model to use. mistral-7b-instruct is free and good enough.
        # Other options: "openai/gpt-3.5-turbo", "anthropic/claude-3-haiku"
        self.model = "mistralai/mistral-7b-instruct"

    # =========================================================================
    def analyze(self, findings_data):
        """
        Main method — takes security findings and returns an AI analysis report.

        Parameters:
            findings_data (dict): The output from checker.py containing results + summary

        Returns:
            str: The AI's analysis as a markdown-formatted string
        """
        logger.info("Preparing security findings for AI analysis...")

        # Step 1: Format the findings into a clear text summary for the AI
        findings_text = self._format_findings_for_prompt(findings_data)

        # Step 2: Build a well-structured prompt
        prompt = self._build_prompt(findings_text)

        # Step 3: Send to OpenRouter API and get the response
        logger.info(f"Sending to AI model: {self.model}")
        analysis = self._call_openrouter(prompt)

        return analysis

    # =========================================================================
    def _format_findings_for_prompt(self, findings_data):
        """
        Converts our JSON findings into a readable text format for the AI.

        AI models understand natural language better than raw JSON.
        A clean text format helps the AI give better, more structured responses.
        """
        lines = []

        # Add the summary stats
        summary = findings_data.get("summary", {})
        severity = summary.get("by_severity", {})

        lines.append("=== SECURITY SCAN SUMMARY ===")
        lines.append(f"Endpoints with findings: {summary.get('endpoints_with_findings', 0)}")
        lines.append(f"Total findings: {summary.get('total_findings', 0)}")
        lines.append(f"Critical: {severity.get('critical', 0)}")
        lines.append(f"High: {severity.get('high', 0)}")
        lines.append(f"Medium: {severity.get('medium', 0)}")
        lines.append(f"Low: {severity.get('low', 0)}")
        lines.append("")

        lines.append("=== DETAILED FINDINGS ===")

        # Format each endpoint's findings
        results = findings_data.get("results", [])
        for result in results:
            lines.append(f"\nEndpoint: {result['endpoint']}")
            lines.append(f"Full URL: {result['full_url']}")
            lines.append("Findings:")

            for finding in result["findings"]:
                # Format each finding on one clean line
                lines.append(
                    f"  [{finding['severity'].upper()}] "
                    f"{finding['type'].replace('_', ' ').title()}: "
                    f"{finding['detail']}"
                )

        return "\n".join(lines)
        # "\n".join(lines) combines all lines into one string with newlines between them

    # =========================================================================
    def _build_prompt(self, findings_text):
        """
        Builds the final prompt to send to the AI.

        PROMPT ENGINEERING TIPS :
        1. Give the AI a ROLE ("You are a security analyst...")
           → Makes it respond with domain expertise
        2. Provide CONTEXT ("This is a security assessment of...")
           → AI needs to know the situation
        3. Give it the DATA (the actual findings)
           → The raw information to analyze
        4. Give CLEAR INSTRUCTIONS about the output format
           → "Respond with these 3 sections:"
        5. Be SPECIFIC about what you want
           → Vague prompts get vague answers
        """

        prompt = f"""You are a senior application security analyst conducting a security assessment.

CONTEXT:
This scan was performed on OWASP Juice Shop (a deliberately vulnerable web application used for security training). The findings below are from an automated security scanner that checked endpoints for:
- Sensitive paths (URLs containing keywords like admin, config, debug)
- Dangerous HTTP methods enabled
- Missing security headers
- Information disclosure in responses

FINDINGS:
{findings_text}

TASK:
Please analyze these findings and provide a structured security report with the following three sections:

## 1. CRITICAL FINDINGS SUMMARY
List the most serious issues found. For each, explain:
- What the issue is
- Why it's dangerous
- How serious it is (Critical/High/Medium/Low)

## 2. PRIORITIZED ENDPOINT LIST
Which endpoints should a security team investigate first? Rank them and explain why each is a priority.

## 3. RECOMMENDED NEXT STEPS
Concrete, actionable recommendations for the security team. Be specific — not just "fix the headers" but HOW to fix them.

Format your response in clear Markdown. Be concise but thorough. Focus on actionable insights, not generic advice."""

        return prompt

    # =========================================================================
    def _call_openrouter(self, prompt):
        """
        Makes the actual API call to OpenRouter.

        HOW THE OPENROUTER API WORKS:
        1. We send a POST request to https://openrouter.ai/api/v1/chat/completions
        2. The request body is JSON with:
           - model: which AI model to use
           - messages: the conversation (just our prompt for now)
        3. The response contains the AI's reply in response["choices"][0]["message"]["content"]

        This follows the "OpenAI format" — most AI APIs use this same structure.
        """

        # HTTP headers for authentication and content type
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            # f"Bearer {self.api_key}" is an f-string — it inserts the variable's value.
            # Result looks like: "Bearer sk-or-v1-abc123..."
            # "Bearer" is standard auth format for APIs.

            "Content-Type": "application/json",
            # Tells the server we're sending JSON data

            "HTTP-Referer": "http://localhost",
            # OpenRouter requires this header (identifies your app)

            "X-Title": "Security Scanner Assignment",
            # Optional — shows up in OpenRouter's dashboard
        }

        # The request body — what we're actually sending to the AI
        body = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",       # "user" means this is our input
                    "content": prompt     # The actual prompt text
                }
            ],
            "max_tokens": 2000,
            # Maximum length of the AI's response (in "tokens" ≈ roughly 0.75 words each)
            # 2000 tokens ≈ ~1500 words

            "temperature": 0.3,
            # Controls randomness (0 = very deterministic, 1 = more creative)
            # For security analysis, lower is better — we want consistent, factual output
        }

        try:
            logger.info("Calling OpenRouter API...")

            response = requests.post(
                self.api_url,
                headers=headers,
                json=body,      # json= automatically serializes the dict to JSON
                timeout=60      # AI responses can take a while — give it 60 seconds
            )

            # .raise_for_status() throws an exception if status code is 4xx or 5xx
            # (4xx = client error, 5xx = server error)
            response.raise_for_status()

            # Parse the JSON response
            data = response.json()

            # Navigate to the AI's actual text response
            # data is a dict → data["choices"] is a list → [0] is first item
            # → ["message"] is another dict → ["content"] is the text
            ai_text = data["choices"][0]["message"]["content"]

            logger.info("AI analysis received successfully.")
            return ai_text

        except requests.exceptions.HTTPError as e:
            # HTTP errors (400, 401, 403, 429, 500...)
            if response.status_code == 401:
                logger.error("Authentication failed — check your API key")
            elif response.status_code == 429:
                logger.error("Rate limit hit — wait a moment and try again")
            else:
                logger.error(f"HTTP error: {e}")
            return f"Error getting AI analysis: {e}"

        except requests.exceptions.Timeout:
            logger.error("Request timed out — the AI is taking too long")
            return "Error: AI analysis timed out. Try again."

        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return f"Error: Could not reach OpenRouter API: {e}"

        except (KeyError, IndexError) as e:
            # If the response format is unexpected
            logger.error(f"Unexpected API response format: {e}")
            logger.error(f"Raw response: {response.text}")
            return "Error: Unexpected response format from API"


# =============================================================================
# RUN THIS FILE DIRECTLY (for testing)
# =============================================================================
if __name__ == "__main__":
    # Load the API key from .env file
    # python-dotenv reads .env files automatically
    try:
        from dotenv import load_dotenv
        load_dotenv()
        print("✅ Loaded .env file")
    except ImportError:
        print("Note: python-dotenv not installed. Reading from system environment.")
        print("Install with: pip install python-dotenv")

    # Load findings from checker.py's output
    try:
        with open("security_findings.json", "r") as f:
            findings_data = json.load(f)
        print(f"✅ Loaded findings: {findings_data['summary']['total_findings']} total findings")
    except FileNotFoundError:
        # Use sample data if the file doesn't exist yet
        print("security_findings.json not found — using sample data")
        findings_data = {
            "summary": {
                "endpoints_with_findings": 3,
                "total_findings": 7,
                "by_severity": {"critical": 0, "high": 2, "medium": 4, "low": 1}
            },
            "results": [
                {
                    "endpoint": "/rest/admin/application-configuration",
                    "full_url": "http://localhost:3000/rest/admin/application-configuration",
                    "findings": [
                        {"type": "sensitive_path", "severity": "high", "detail": "URL contains 'admin'"},
                        {"type": "missing_header", "severity": "medium", "detail": "Missing Content-Security-Policy"}
                    ]
                },
                {
                    "endpoint": "/api/Users",
                    "full_url": "http://localhost:3000/api/Users",
                    "findings": [
                        {"type": "missing_header", "severity": "medium", "detail": "Missing X-Frame-Options"},
                        {"type": "information_disclosure", "severity": "medium", "detail": "Server version exposed"}
                    ]
                }
            ]
        }

    # Create the analyzer and run analysis
    analyzer = AIAnalyzer()  # Will read API key from environment
    report = analyzer.analyze(findings_data)

    print("\n" + "="*60)
    print("AI SECURITY ANALYSIS REPORT")
    print("="*60)
    print(report)

    # Save the report
    with open("ai_report.md", "w") as f:
        f.write("# AI Security Analysis Report\n\n")
        f.write(report)
    print("\n✅ Report saved to ai_report.md")
