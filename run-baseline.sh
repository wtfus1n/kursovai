#!/usr/bin/env bash
set -euo pipefail

if (( $# < 2 )); then
    echo "Usage: bash run-baseline.sh NS3_DIRECTORY aodv|olsr [scenario options]" >&2
    exit 2
fi

source_dir=$1
protocol=$2
shift 2
case "$protocol" in
    aodv|olsr) ;;
    *) echo "Protocol must be aodv or olsr." >&2; exit 2 ;;
esac

cd -- "$source_dir"
if [[ ! -f VERSION || ! -x ./ns3 ]] || [[ $(<VERSION) != 3.49 ]]; then
    echo "Specify an NS-3.49 directory." >&2
    exit 2
fi

target="$protocol-baseline"
if [[ ! -f "scratch/$target.cc" ]]; then
    echo "Apply the baseline patch for $protocol first." >&2
    exit 2
fi

./ns3 run "$target" -- "$@"
