#!/usr/bin/env python3
"""Create an isolated ns-3.49 variant; never patch the supplied source tree."""

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=pathlib.Path, help="Clean ns-3.49 source directory")
    parser.add_argument("destination", type=pathlib.Path, help="New, nonexistent working directory")
    parser.add_argument("--protocol", choices=("aodv", "olsr"), required=True)
    parser.add_argument("--attack", choices=("blackhole", "grayhole", "wormhole", "sybil"), required=True)
    parser.add_argument("--check-only", action="store_true", help="Check source and patch without copying")
    parser.add_argument("--comparison", action="store_true",
                        help="Install the shared AODV/OLSR comparison scenario")
    args = parser.parse_args()
    source = args.source.expanduser().resolve()
    destination = args.destination.expanduser().resolve(strict=False)
    bundle = pathlib.Path(__file__).resolve().parent
    version = source / "VERSION"
    if not version.is_file() or version.read_text().strip() != "3.49":
        parser.error("The source must contain VERSION exactly equal to 3.49")
    if not shutil.which("patch"):
        parser.error("GNU patch is required (Linux: install the patch package)")
    name = f"ns3-49-{args.protocol}-{args.attack}.patch"
    patch = bundle / name
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest["patches"][name]
    if hashlib.sha256(patch.read_bytes()).hexdigest() != entry["sha256"]:
        parser.error(f"Bundle integrity check failed for {name}")
    for relpath, expected in entry["upstream_files"].items():
        item = source / relpath
        if not item.is_file() or hashlib.sha256(item.read_bytes()).hexdigest() != expected:
            parser.error(f"Source differs from the tested clean ns-3.49: {relpath}")
    for relpath in entry.get("created_files", []):
        if (source / relpath).exists():
            parser.error(f"Expected a clean source tree without {relpath}")
    command = ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(patch)]
    subprocess.run(command + ["--dry-run"], cwd=source, check=True)
    if args.check_only:
        print(f"PASS: {name} applies to the unchanged source; no files were modified")
        return
    if destination.exists():
        parser.error("Destination already exists; choose a new empty path")
    if destination == source or source in destination.parents:
        parser.error("Destination must be outside the supplied source tree")
    # Captures and trace files below src/ can be upstream regression fixtures.
    ignore_root = shutil.ignore_patterns(".git", "build", "cmake-cache", "__pycache__", ".lock-ns3*")

    def ignore(directory, names):
        if pathlib.Path(directory) == source:
            return ignore_root(directory, names)
        return []

    shutil.copytree(source, destination, ignore=ignore)
    subprocess.run(command, cwd=destination, check=True)
    tests = bundle / "tests"
    scratch = destination / "scratch"
    for filename in entry.get("scenario_files", []):
        shutil.copy2(tests / filename, scratch / filename)
    if args.comparison:
        comparison = (bundle / "experiments" / "matched-attacks.cc").read_text(encoding="utf-8")
        definitions = (
            f"#define SCALE_AODV {int(args.protocol == 'aodv')}\n"
            f'#define SCALE_ATTACK "{args.attack}"\n'
            f"#define SCALE_WORMHOLE {int(args.attack == 'wormhole')}\n"
            f"#define SCALE_SYBIL {int(args.attack == 'sybil')}\n"
        )
        (scratch / "matched-attacks.cc").write_text(definitions + comparison, encoding="utf-8")
    print(f"Prepared {destination}")
    print("The original source is unchanged. Build and run the checks described in README.md.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit(f"ERROR: {error}")
