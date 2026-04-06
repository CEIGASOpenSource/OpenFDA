"""Entry point wrapper for PyInstaller builds.

This top-level script ensures:
1. The fda package resolves correctly when frozen
2. Any crash shows the error instead of closing the window
"""
import sys
import traceback

try:
    from fda.__main__ import main
    main()
except SystemExit:
    # Normal exit — still pause if interactive
    if sys.stdout and sys.stdout.isatty():
        try:
            input("\n  Press Enter to close...")
        except (EOFError, KeyboardInterrupt):
            pass
except Exception:
    print("\n  OpenFDA encountered an error:\n")
    traceback.print_exc()
    print()
    try:
        input("  Press Enter to close...")
    except (EOFError, KeyboardInterrupt):
        pass
    sys.exit(1)
