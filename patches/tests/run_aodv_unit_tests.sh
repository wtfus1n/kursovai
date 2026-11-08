#!/usr/bin/env bash
set -euo pipefail
# Run the unmodified upstream AODV suites without building every Wi-Fi test DSO.
# Usage: bash /path/to/patches/tests/run_aodv_unit_tests.sh /path/to/ns-3.49
cd "${1:?Pass the NS-3.49 source directory}"
./ns3 build aodv-test -j "${JOBS:-4}"
mkdir -p build/utils
g++ -std=c++23 -Ibuild/include utils/test-runner.cc -Lbuild/lib \
    -Wl,--no-as-needed -lns3.49-aodv-test-default -lns3.49-core-default \
    -o build/utils/aodv-unit-runner
export LD_LIBRARY_PATH="$PWD/build/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
for suite in aodv-routing-id-cache routing-aodv routing-aodv-loopback routing-aodv-regression; do
    build/utils/aodv-unit-runner --suite="$suite" --verbose
done
