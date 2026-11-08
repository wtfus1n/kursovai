#!/usr/bin/env bash
set -euo pipefail

bundle=$(cd "$(dirname "$0")/.." && pwd)
upstream="$HOME/ns3-work/ns-3.49"
results=${1:-"$bundle/tests/results/scale-100"}
mkdir -p "$results"
results=$(cd "$results" && pwd)
tree="$(mktemp -d "$HOME/ns3-work/scale-100.XXXXXXXX")/ns-3.49"
printf '%s\n' "$tree" > "$results/build-dir.txt"
{
    python3 "$bundle/prepare_variant.py" "$upstream" "$tree" --protocol aodv --attack blackhole
    cd "$tree"
    export CMAKE_CXX_COMPILER_LAUNCHER=ccache
    ./ns3 configure --build-profile release --enable-modules=aodv,olsr,applications,point-to-point --disable-python-bindings
    ./ns3 build aodv olsr applications point-to-point -j 12
} > "$results/build-initial.log" 2>&1
