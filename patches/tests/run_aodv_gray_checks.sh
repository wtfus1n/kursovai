#!/usr/bin/env bash
set -euo pipefail
cd "${1:?Pass the NS-3.49 source directory}"
results="${2:?Pass the output directory}"
./ns3 run 'aodv-drop-check --checkAutomaticStreams=1' --no-build > "$results/aodv-grayhole-automatic-streams.log" 2>&1
./ns3 run 'aodv-drop-check --malicious=0' --no-build > "$results/aodv-grayhole-baseline.log" 2>&1
./ns3 run 'aodv-drop-check --malicious=1 --probability=0' --no-build > "$results/aodv-grayhole-p0.log" 2>&1
./ns3 run 'aodv-drop-check --malicious=1 --probability=0.5 --seed=17 --run=1' --no-build > "$results/aodv-grayhole-p05.log" 2>&1
./ns3 run 'aodv-drop-check --malicious=1 --probability=0.5 --seed=17 --run=1' --no-build > "$results/aodv-grayhole-p05-repeat.log" 2>&1
cmp "$results/aodv-grayhole-p05.log" "$results/aodv-grayhole-p05-repeat.log"
./ns3 run 'aodv-drop-check --malicious=1 --probability=1' --no-build > "$results/aodv-grayhole-p1.log" 2>&1
./ns3 run 'aodv-drop-check --malicious=1 --probability=0.5 --seed=17 --run=2' --no-build > "$results/aodv-grayhole-p05-run2.log" 2>&1
