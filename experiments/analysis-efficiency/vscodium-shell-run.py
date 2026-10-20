#!/usr/bin/env python3
"""Run the real VSCodium shell-producer verifier in a private Linux namespace."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def revision(path):
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=path, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def main():
    started = time.monotonic()
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["runtime-root", "node", "executable", "application", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--memory-gib", type=int, choices=[4, 8], default=4)
    args = parser.parse_args()
    home = Path.home()
    for target in [home / ".config", home / ".local"]:
        if not target.is_dir():
            raise SystemExit(f"Existing mount target required; no host directory created: {target}")
    scripts = Path(__file__).resolve().parent
    source_root = scripts.parent.parent
    runtime = args.runtime_root.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    trial = Path(tempfile.mkdtemp(prefix="vscodium-shell-", dir=args.output.resolve()))
    (trial / "OWNED-BY-REA-3474").write_text("REA3474 owned disposable verification trial\n")
    for name in ["config", "tmp", "local/state", "local/share"]:
        (trial / name).mkdir(parents=True)
    verifier = scripts / "vscodium-shell-producer.mjs"
    files = {
        "runner": Path(__file__).resolve(),
        "verifier": verifier,
        "resource-run": scripts / "resource-run.py",
        "resource-payload": scripts / "resource_payload.py",
        "shell-boundary": runtime / "scripts/electron-active-hook-boundaries.cjs",
        "shared-environment": runtime / "dist/browser/PlaywrightElectronActiveProvider.js",
        "owned-copy-source": runtime / "README.md",
        "node": args.node.resolve(),
        "selected-executable": args.executable.resolve(),
    }
    pins = {
        "verifier_source": revision(source_root), "runtime_source": revision(runtime),
        "inputs": {key: str(value) if isinstance(value, Path) else value
                   for key, value in vars(args).items()},
        "files": {name: {"path": str(path), "sha256": digest(path)} for name, path in files.items()},
    }
    (trial / "source-pins.json").write_text(json.dumps(pins, indent=2) + "\n")
    command = [
        sys.executable, str(scripts / "resource-run.py"),
        "--memory-gib", str(args.memory_gib), "--observe-payload-exit", "--", "env",
        f"PATH={args.node.resolve().parent}:/usr/bin:/bin", "GOMAXPROCS=1", "GOMEMLIMIT=3GiB",
        "UV_THREADPOOL_SIZE=1", "NODE_OPTIONS=--max-old-space-size=2048", f"TMPDIR={trial}/tmp",
        "xvfb-run", "-a", "-f", str(trial / "Xauthority"),
        "--server-args=-screen 0 1280x900x24 -nolisten tcp -ac",
        "bwrap", "--die-with-parent", "--new-session", "--ro-bind", "/", "/",
        "--dev-bind", "/dev", "/dev", "--proc", "/proc",
        "--bind", str(trial), str(trial),
        "--bind", str(trial / "config"), str(home / ".config"),
        "--bind", str(trial / "local"), str(home / ".local"),
        str(args.node.resolve()), str(verifier), "--runtime-root", str(runtime),
        "--executable", str(args.executable.resolve()),
        "--application", str(args.application.resolve()), "--trial-root", str(trial),
    ]
    (trial / "invocation.json").write_text(json.dumps(command, indent=2) + "\n")
    print(json.dumps({"trial": str(trial), "source": pins["verifier_source"],
                      "runtime_source": pins["runtime_source"]}), flush=True)
    result = subprocess.run(command, cwd=source_root, check=False)
    (trial / "execution.json").write_text(json.dumps({
        "exit_code": result.returncode, "driver_wall_seconds": time.monotonic() - started,
        "scope": "Driver wall includes source hashing/preparation; acquisition and agent costs unmeasured.",
    }) + "\n")
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
