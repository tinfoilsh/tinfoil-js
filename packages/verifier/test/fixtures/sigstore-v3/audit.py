#!/usr/bin/env python3
"""Replay the frozen crypto cases with the pinned Go reference implementation."""
import os
import pathlib
import subprocess
import sys

checkout = pathlib.Path(sys.argv[1]).resolve()
revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip()
if revision != "0ad2c4addae02b7aac7ba9d11d98e2726b82d177":
    raise RuntimeError(f"Expected pinned Go reference 0ad2c4addae02b7aac7ba9d11d98e2726b82d177, found {revision}")
directory = pathlib.Path(__file__).resolve().parent
helper = checkout / "verify/internal/endorsement/zz_js_sigstore_boundaries_test.go"
if helper.exists():
    raise RuntimeError("temporary audit already exists")
try:
    helper.write_bytes(directory.joinpath("audit.go.txt").read_bytes())
    subprocess.run(["go", "test", "./verify/internal/endorsement", "-run", "^TestAuditJSSigstoreBoundaries$", "-count=1"], cwd=checkout, env={**os.environ, "GOWORK": "off", "TINFOIL_JS_SIGSTORE_FIXTURES": str(directory)}, check=True)
finally:
    helper.unlink(missing_ok=True)
