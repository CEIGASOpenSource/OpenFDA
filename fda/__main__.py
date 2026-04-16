"""CeigasFDA entry point.

Usage:
    ceigasfda <challenge-nonce>           # Scan, review, submit
    ceigasfda <challenge-nonce> --key K   # Scan with HMAC signing
    ceigasfda --preview                   # Scan without signing or sending

Or just double-click — the program will ask for your nonce.

The FDA scans the local environment, checks hard gates, and produces
a signed report for CEIGAS personal computer provisioning.
"""

import argparse
import json
import sys
import urllib.request
import urllib.error

from fda.gates import run_all_gates
from fda.scan import run_full_scan
from fda.scan.account import scan_account
from fda.scan.drives import scan_drives
from fda.scan.resources import scan_resources
from fda.scan.profile import scan_profile
from fda.scan.tools import scan_tools
from fda.scan.ai_environment import scan_ai_environment
from fda.report.builder import build_report, report_to_json
from fda.report.display import display_report

# Default submit endpoint — users don't need to think about this
DEFAULT_SUBMIT_URL = "https://privatae.ai/api/mastercode/fda/submit"

VERSION = "1.5.0"

BANNER = f"""
  ╔═══════════════════════════════════════════╗
  ║          CeigasFDA — Environment Scan       ║
  ║       Personal Computer Setup             ║
  ║                                v{VERSION}    ║
  ╚═══════════════════════════════════════════╝
"""


def _run_scan_with_progress(interactive: bool) -> dict:
    """Run each scan step individually with progress output."""
    steps = [
        ("account", "Account info", scan_account),
        ("drives", "Drive mapping", scan_drives),
        ("resources", "System resources", scan_resources),
        ("profile", "User profile", scan_profile),
        ("tools", "Installed tools", scan_tools),
        ("ai_environment", "AI environment", scan_ai_environment),
    ]
    results = {}
    for key, label, fn in steps:
        if interactive:
            print(f"    {label}...", end="", flush=True)
        try:
            results[key] = fn()
            if interactive:
                print(" done")
        except Exception as e:
            results[key] = {"error": str(e)}
            if interactive:
                print(f" error: {e}")
    # Match the keys run_full_scan uses
    return {
        "platform": results.get("account", {}),
        "drives": results.get("drives", []),
        "resources": results.get("resources", {}),
        "user_profile": results.get("profile", {}),
        "tools": results.get("tools", {}),
        "ai_environment": results.get("ai_environment", {}),
    }


def _pause_before_exit(code: int = 0):
    """Pause so the window stays open when double-clicked."""
    try:
        input("\n  Press Enter to close...")
    except (EOFError, KeyboardInterrupt):
        pass
    sys.exit(code)


def main():
    parser = argparse.ArgumentParser(
        prog="ceigasfda",
        description="CeigasFDA — Forward Deployed Agent for personal computer provisioning",
    )
    parser.add_argument(
        "challenge",
        nargs="?",
        help="Platform-issued challenge nonce (paste from the setup screen)",
    )
    parser.add_argument(
        "--challenge", "-c",
        dest="challenge_flag",
        help=argparse.SUPPRESS,  # Hidden — kept for backward compat
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
        default=DEFAULT_SUBMIT_URL,
        help=argparse.SUPPRESS,  # Hidden — default handles it
    )
    parser.add_argument(
        "--no-submit",
        action="store_true",
        help="Scan and display only — do not send to platform",
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

    # Accept challenge as positional arg OR --challenge flag
    nonce = args.challenge or args.challenge_flag

    # ── Interactive mode: no args, ask the user ───────────────
    if not args.preview and not nonce:
        print(BANNER)
        print("  Paste your challenge nonce from the Privatae setup screen.")
        print("  (It's the code shown after you click 'Get Started')\n")
        try:
            nonce = input("  Challenge nonce: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Cancelled.\n")
            _pause_before_exit(0)

        if not nonce:
            print("\n  No nonce provided. Run with --preview to scan without submitting.\n")
            _pause_before_exit(1)

    nonce = nonce or "preview-mode"
    identity_key = args.key
    should_submit = not args.preview and not args.no_submit
    interactive = not args.json_only

    if interactive and not args.preview:
        print(BANNER)

    # ── Step 1: Hard gates ────────────────────────────────────
    if interactive:
        print("  Scanning environment...\n")

    try:
        gates = run_all_gates()
    except Exception as e:
        print(f"  Error during gate scan: {e}\n")
        _pause_before_exit(1)

    # If any gate triggers, show rejection and exit
    if gates["verdict"] == "REJECT":
        report = build_report(gates, {}, nonce)
        if args.json_only:
            print(report_to_json(report))
        else:
            print(display_report(report))
        _pause_before_exit(1)

    # ── Step 2: Full environment scan ─────────────────────────
    try:
        scan = _run_scan_with_progress(interactive)
    except Exception as e:
        print(f"  Error during environment scan: {e}\n")
        _pause_before_exit(1)

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
        if interactive:
            print(f"  Report saved to: {args.output}\n")

    # ── Step 6: Submit ────────────────────────────────────────
    if should_submit:
        if interactive:
            try:
                confirm = input("  Send this report to the platform? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                confirm = ""
            if confirm != "y":
                print("  Cancelled. Report not sent.\n")
                _pause_before_exit(0)

        success = _submit_report(report, args.submit_url, args.json_only)
        _pause_before_exit(0 if success else 1)

    if interactive and not should_submit:
        if args.preview:
            print("  Preview mode — report not signed or sent.\n")
        else:
            print("  Report generated. Run without --no-submit to send.\n")
        _pause_before_exit(0)


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
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"CeigasFDA/{VERSION} (privatae.ai; environment-scan)",
            },
            method="POST",
        )

        if not quiet:
            print("  Sending report...")

        with urllib.request.urlopen(req, timeout=30) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")

        if status == 200:
            if not quiet:
                print("  Report submitted successfully!\n")
                try:
                    resp_data = json.loads(body)
                    if resp_data.get("status") == "received":
                        print("  Your entity has received the scan. Return to the")
                        print("  setup screen in your browser to continue.\n")
                except json.JSONDecodeError:
                    pass
            return True
        else:
            if not quiet:
                print(f"  Submission failed: HTTP {status}\n")
                print(f"  Response: {body[:200]}\n")
            return False

    except urllib.error.HTTPError as e:
        if not quiet:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            print(f"  Submission failed: HTTP {e.code}\n")
            print(f"  URL: {url}")
            print(f"  Response: {body[:500]}\n")
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
