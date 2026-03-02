# =============================================================================
# main.py — The Orchestrator: Ties Parts 1, 2, and 3 Together
# =============================================================================
#
# WHAT THIS FILE DOES:
#   Runs the full security scanner pipeline:
#   1. Crawl the target → find endpoints
#   2. Run security checks on each endpoint → find issues
#   3. Send findings to AI → get analysis report
#   4. Save everything to output files

import argparse    # For parsing command-line arguments
import json
import os
import sys
import logging
from datetime import datetime

# Import our own modules (the files we just built)
from crawler import Crawler
from checker import SecurityChecker
from ai_analysis import AIAnalyzer

# Try to load .env file (for API key)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv is optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


# =============================================================================
# COMMAND-LINE ARGUMENT PARSING
# =============================================================================
# argparse lets users customize the tool from the terminal.
# Instead of hardcoding values, users can do:
#   python main.py --url http://localhost:3000 --depth 3

def parse_args():
    parser = argparse.ArgumentParser(
        description="Mini Security Scanner with AI Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py
  python main.py --url http://localhost:3000 --depth 3
  python main.py --skip-ai
  python main.py --no-crawl   (use previously saved endpoints.json)
        """
    )

    parser.add_argument(
        "--url",
        default="http://localhost:3000",
        help="Target URL to scan (default: http://localhost:3000)"
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=2,
        help="Maximum crawl depth (default: 2)"
    )
    parser.add_argument(
        "--skip-ai",
        action="store_true",
        help="Skip the AI analysis step (useful if no API key)"
    )
    parser.add_argument(
        "--no-crawl",
        action="store_true",
        help="Skip crawling — load endpoints from endpoints.json"
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory to save output files (default: current directory)"
    )

    return parser.parse_args()


# =============================================================================
# MAIN PIPELINE
# =============================================================================

def main():
    args = parse_args()

    print("\n" + "="*60)
    print("  🔍  MINI SECURITY SCANNER WITH AI ANALYSIS")
    print("="*60)
    print(f"  Target:    {args.url}")
    print(f"  Max Depth: {args.depth}")
    print(f"  AI Analysis: {'Disabled' if args.skip_ai else 'Enabled'}")
    print("="*60 + "\n")

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    # Track start time (so we can report how long the scan took)
    start_time = datetime.now()

    # =========================================================================
    # PART 1: CRAWLING
    # =========================================================================
    print("\n📡 PART 1: ENDPOINT DISCOVERY\n" + "-"*40)

    endpoints_file = os.path.join(args.output_dir, "endpoints.json")

    if args.no_crawl:
        # Load previously saved endpoints
        try:
            with open(endpoints_file, "r") as f:
                endpoints_data = json.load(f)
            endpoints = endpoints_data["endpoints_found"]
            print(f"Loaded {len(endpoints)} endpoints from {endpoints_file}")
        except FileNotFoundError:
            print(f"Error: {endpoints_file} not found. Run without --no-crawl first.")
            sys.exit(1)
    else:
        crawler = Crawler(base_url=args.url, max_depth=args.depth)
        endpoints = crawler.crawl()

        # Save crawler output
        endpoints_data = {
            "base_url": args.url,
            "endpoints_found": endpoints,
            "total_count": len(endpoints),
            "scan_time": start_time.isoformat()
        }
        with open(endpoints_file, "w") as f:
            json.dump(endpoints_data, f, indent=2)

        print(f"\n✅ Found {len(endpoints)} unique endpoints")
        print(f"   Saved to: {endpoints_file}")

    # =========================================================================
    # PART 2: SECURITY CHECKS
    # =========================================================================
    print("\n\n🔒 PART 2: SECURITY CHECKS\n" + "-"*40)
    print(f"Running checks on {len(endpoints)} endpoints...\n")

    checker = SecurityChecker(base_url=args.url)
    results = checker.check_all(endpoints)
    stats = checker.get_summary_stats(results)

    # Build full findings output
    findings_data = {
        "scan_info": {
            "target": args.url,
            "scan_time": start_time.isoformat(),
            "endpoints_checked": len(endpoints)
        },
        "summary": stats,
        "results": results
    }

    findings_file = os.path.join(args.output_dir, "security_findings.json")
    with open(findings_file, "w") as f:
        json.dump(findings_data, f, indent=2)

    # Print a mini summary to the console
    print(f"\n✅ Security checks complete!")
    print(f"   Endpoints with issues: {stats['endpoints_with_findings']}")
    print(f"   Total findings: {stats['total_findings']}")
    print(f"   Severity breakdown:")
    for severity, count in stats['by_severity'].items():
        if count > 0:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
            print(f"     {emoji} {severity.capitalize()}: {count}")
    print(f"   Saved to: {findings_file}")

    # =========================================================================
    # PART 3: AI ANALYSIS
    # =========================================================================
    if not args.skip_ai:
        print("\n\n🤖 PART 3: AI ANALYSIS\n" + "-"*40)

        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            print("⚠️  No OPENROUTER_API_KEY found in environment.")
            print("   Create a .env file with: OPENROUTER_API_KEY=your-key-here")
            print("   Or run with: --skip-ai")
            print("   Skipping AI analysis...")
        else:
            try:
                analyzer = AIAnalyzer(api_key=api_key)
                report = analyzer.analyze(findings_data)

                # Save the report as markdown
                report_file = os.path.join(args.output_dir, "ai_report.md")
                scan_date = start_time.strftime("%Y-%m-%d %H:%M:%S")
                with open(report_file, "w") as f:
                    f.write(f"# Security Scan Report\n")
                    f.write(f"**Target:** {args.url}  \n")
                    f.write(f"**Date:** {scan_date}  \n")
                    f.write(f"**Endpoints Scanned:** {len(endpoints)}  \n\n")
                    f.write("---\n\n")
                    f.write(report)

                print(f"\n✅ AI analysis complete!")
                print(f"   Saved to: {report_file}")
                print("\n" + "="*60)
                print("AI REPORT PREVIEW:")
                print("="*60)
                # Print first 2000 chars as preview
                print(report[:2000])
                if len(report) > 2000:
                    print(f"\n... [truncated — see {report_file} for full report]")

            except Exception as e:
                print(f"⚠️  AI analysis failed: {e}")

    # =========================================================================
    # FINAL SUMMARY
    # =========================================================================
    elapsed = (datetime.now() - start_time).seconds
    print("\n\n" + "="*60)
    print("  ✅  SCAN COMPLETE")
    print("="*60)
    print(f"  Time elapsed:  {elapsed} seconds")
    print(f"  Output files:")
    print(f"    📄 {endpoints_file}")
    print(f"    📄 {findings_file}")
    if not args.skip_ai and api_key:
        report_file = os.path.join(args.output_dir, "ai_report.md")
        print(f"    📄 {report_file}")
    print("="*60 + "\n")


# =============================================================================
if __name__ == "__main__":
    main()
