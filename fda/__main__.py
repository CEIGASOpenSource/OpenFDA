"""OpenFDA entry point.

Usage:
    python3 -m fda --challenge <nonce>
    python3 -m fda --challenge <nonce> --key <identity_lock_key>
    python3 -m fda --preview          # Run scan without signing or sending

The FDA scans the local environment, checks hard gates, and produces
a signed report for CEIGAS relay provisioning.
"""

import argparse
import json
import sys
import urllib.request
import urllib.error

from fda.gates import run_all_gates
from fda.scan import run_full_scan
from fda.report.builder import build_report, report_to_json
from fda.report.display import display_report


def main():
    parser = argparse.ArgumentParser(
        prog="openfda",
        description="OpenFDA — Forward Deployed Agent for CEIGAS relay provisioning",
    )
    parser.add_argument(
        "--challenge", "-c",
        help="Platform-issued challenge nonce (required for signed reports)",
    )
    parser.add_argument(
        "--key", "-k",
        help="Identity lock key for HMAC signing",
    )
    parser.add_argument(
        "--preview", "-p",
        action="store_true",
        help="Preview mode — scan and display without signing or sending",
    )
    parser.add_argument(
        "--submit-url",
        help="Platform API URL to submit the report to",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Output raw JSON only (for piping/automation)",
    )
    parser.add_argument(
        "--output", "-o",
        help="Write report JSON to file",
    )
    args = parser.parse_args()

    if not args.preview and not args.challenge:
        parser.error("--challenge is required (or use --preview for unsigned scan)")

    nonce = args.challenge or "preview-mode"
    identity_key = args.key

    # ── Step 1: Hard gates ────────────────────────────────────
    if not args.json_only:
        print("\n  Scanning environment...\n")

    gates = run_all_gates()

    # If any gate triggers, show rejection and exit
    if gates["verdict"] == "REJECT":
        report = build_report(gates, {}, nonce)
        if args.json_only:
            print(report_to_json(report))
        else:
            print(display_report(report))
        sys.exit(1)

    # ── Step 2: Full environment scan ─────────────────────────
    scan = run_full_scan()

    # ── Step 3: Build report ──────────────────────────────────
    report = build_report(gates, scan, nonce, identity_key)

    # ── Step 4: Display to user ───────────────────────────────
    if args.json_only:
        print(report_to_json(report))
    else:
        print(display_report(report))

    # ── Step 5: Save to file if requested ─────────────────────
    if args.output:
        with open(args.output, "w") as f:
            f.write(report_to_json(report))
        if not args.json_only:
            print(f"  Report saved to: {args.output}\n")

    # ── Step 6: Submit if URL provided and user confirms ──────
    if args.submit_url and not args.preview:
        if not args.json_only:
            confirm = input("  Send this report to the platform? [y/N] ").strip().lower()
            if confirm != "y":
                print("  Cancelled. Report not sent.\n")
                sys.exit(0)

        success = _submit_report(report, args.submit_url, args.json_only)
        sys.exit(0 if success else 1)

    if not args.json_only and not args.submit_url:
        if args.preview:
            print("  Preview mode — report not signed or sent.\n")
        else:
            print("  Report ready. Use --submit-url to send to platform,")
            print("  or --output to save for manual submission.\n")


def _submit_report(report: dict, url: str, quiet: bool = False) -> bool:
    """Submit signed report to platform API."""
    try:
        # Wrap report in the format the platform API expects
        attestation = report.get("attestation", {})
        payload = {
            "nonce": attestation.get("nonce", ""),
            "report": report,
            "environment_hash": attestation.get("environment_hash", ""),
            "hmac_signature": attestation.get("hmac"),
            "machine_id": attestation.get("machine_id"),
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")

        if status == 200:
            if not quiet:
                print("  Report submitted successfully.\n")
                try:
                    resp_data = json.loads(body)
                    if resp_data.get("message"):
                        print(f"  Platform: {resp_data['message']}\n")
                except json.JSONDecodeError:
                    pass
            return True
        else:
            if not quiet:
                print(f"  Submission failed: HTTP {status}\n")
                print(f"  Response: {body[:200]}\n")
            return False

    except urllib.error.URLError as e:
        if not quiet:
            print(f"  Connection failed: {e}\n")
        return False
    except Exception as e:
        if not quiet:
            print(f"  Error: {e}\n")
        return False


if __name__ == "__main__":
    main()
