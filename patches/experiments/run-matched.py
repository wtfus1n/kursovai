#!/usr/bin/env python3
"""Build independent NS-3.49 variants and collect the paired 5,040-run matrix."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import itertools
import json
from pathlib import Path
import shutil
import subprocess
import sys

BUNDLE = Path(__file__).resolve().parents[1]
SOURCE = BUNDLE / "experiments/matched-attacks.cc"
MANIFEST = json.loads((BUNDLE / "manifest.json").read_text())
TOPOLOGIES = [("grid", 0), ("grid", 1), ("triangle", 0), ("ring", 0)]


def conditions(attack):
    yield ("off", 0, .5, 1, 3)
    if attack in ("blackhole", "grayhole"):
        for control, probability in itertools.product((0, 1), (.25, .5, .75) if attack == "grayhole" else (1,)):
            yield ("attack", control, probability, 1, 3)
    elif attack == "wormhole":
        for mode, delay in itertools.product(("control-only", "control-and-data"), (1, 10, 50)):
            yield (mode, 0, .5, delay, 3)
    else:
        for identities in (1, 3, 10):
            yield ("attack", 0, .5, 1, identities)


def build(tree, upstream, name, entry, logfile):
    protocol, attack = entry["protocol"], entry["attack"]
    for relative in {r for item in MANIFEST["patches"].values() for r in item["upstream_files"]}:
        if (tree / relative).read_bytes() != (upstream / relative).read_bytes():
            shutil.copyfile(upstream / relative, tree / relative)
    for relative in {r for item in MANIFEST["patches"].values() for r in item.get("created_files", [])}:
        (tree / relative).unlink(missing_ok=True)
    definitions = (f"#define SCALE_AODV {int(protocol == 'aodv')}\n"
                   f'#define SCALE_ATTACK "{attack}"\n'
                   f"#define SCALE_WORMHOLE {int(attack == 'wormhole')}\n"
                   f"#define SCALE_SYBIL {int(attack == 'sybil')}\n")
    (tree / "scratch/matched-attacks.cc").write_text(definitions + SOURCE.read_text())
    with logfile.open("a") as log:
        for command in ([sys.executable, BUNDLE / "prepare_variant.py", upstream, tree,
                         "--protocol", protocol, "--attack", attack, "--comparison", "--check-only"],
                        ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", BUNDLE / name],
                        ["./ns3", "build", "matched-attacks", "-j", "12"]):
            subprocess.run(command, cwd=tree, stdout=log, stderr=subprocess.STDOUT, check=True)
    return next(p for p in (tree / "build/scratch").glob("ns3.49-matched-attacks*") if p.is_file())


def simulate(binary, protocol, attack, job, timeout):
    (topology, redundant), nodes, (mode, plane, probability, delay, identities), run = job
    args = [str(binary), f"--topology={topology}", f"--redundant={redundant}", f"--nodes={nodes}",
            f"--mode={mode}", f"--controlPlaneAttack={plane}", f"--tunnelDelayMs={delay}",
            f"--identities={identities}", f"--run={run}", "--seed=49"]
    if attack == "grayhole":
        args.append(f"--probability={probability}")
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=True)
    matches = [line[7:] for line in p.stdout.splitlines() if line.startswith("RESULT ")]
    if len(matches) != 1:
        raise ValueError(p.stdout[-400:])
    data = json.loads(matches[0])
    expected = dict(protocol=protocol, attack=attack, topology=topology, redundant=redundant,
                    nodes=nodes, mode=mode, control_plane_attack=plane, tunnel_delay_ms=delay,
                    identities=identities, run=run, seed=49,
                    probability=1 if attack == "blackhole" else probability)
    if any(data[k] != v for k,v in expected.items()):
        raise ValueError("Metadata mismatch")
    flows = data["flows"]
    if len(flows)!=8 or sum(f["cross"] for f in flows)!=4 or any(
        f["sent"]!=80 or not 0<=f["tunneled_received"]<=f["received"] or
        not 0<=f["socket_accepted"]<=f["sent"] for f in flows
    ):
        raise ValueError("Traffic counters mismatch")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tree", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--upstream", type=Path, default=Path.home() / "ns3-work/ns-3.49")
    parser.add_argument("--workers", type=int, default=14)
    parser.add_argument("--timeout", type=int, default=150)
    args = parser.parse_args()
    tree = args.tree.resolve(strict=True)
    if tree == args.upstream.resolve() or not (tree / "cmake-cache/CMakeCache.txt").is_file():
        parser.error("Choose a configured copy of NS-3.49 distinct from upstream")
    args.out.mkdir(parents=True, exist_ok=True)
    provenance = {"source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                  "patch_sha256": {n:e["sha256"] for n,e in MANIFEST["patches"].items()}}
    receipt = args.out / "provenance.json"
    if receipt.exists() and json.loads(receipt.read_text()) != provenance:
        parser.error("Use a new output directory for changed sources or patches")
    receipt.write_text(json.dumps(provenance,indent=2)+"\n")
    failures = 0
    with (tree / ".matched-campaign.lock").open("w") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
        for name, entry in MANIFEST["patches"].items():
            protocol, attack = entry["protocol"], entry["attack"]
            stem = f"{protocol}-{attack}"
            jobs = list(itertools.product(TOPOLOGIES,(25,50,100),conditions(attack),range(1,11)))
            dest = args.out / (stem+".jsonl")
            existing = {}
            if dest.exists():
                for line in dest.read_text().splitlines():
                    k, result = json.loads(line)
                    existing[k] = result
            work = [(json.dumps(job),job) for job in jobs if json.dumps(job) not in existing]
            print(f"{stem}: {len(existing)}/{len(jobs)} cached, {len(work)} remaining",flush=True)
            if not work:
                continue
            try:
                binary = build(tree,args.upstream,name,entry,args.out/(stem+"-build.log"))
            except subprocess.CalledProcessError:
                print(f"{stem}: build failed",flush=True)
                failures += len(work)
                continue
            def execute(item):
                key, job = item
                try:
                    return key, simulate(binary,protocol,attack,job,args.timeout), None
                except (subprocess.SubprocessError, ValueError, KeyError) as error:
                    return key, None, repr(error)+ " " + str(getattr(error,"stderr",""))[-2000:]
            with ThreadPoolExecutor(max_workers=args.workers) as pool, dest.open("a") as raw, (
                args.out/(stem+"-errors.log")).open("w") as errors:
                for i,(key,result,error) in enumerate(pool.map(execute,work),1):
                    if error:
                        errors.write(f"{key}\t{error}\n")
                        errors.flush()
                        failures += 1
                    else:
                        raw.write(json.dumps([key,result],separators=(",",":"))+"\n")
                        raw.flush()
                    if i%120==0 or i==len(work):
                        print(f"{stem}: processed {i}/{len(work)}, cumulative failures {failures}",flush=True)
    return int(failures > 0)


if __name__ == "__main__":
    sys.exit(main())

