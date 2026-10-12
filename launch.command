#!/usr/bin/env bash
# Crypton - double-click from Finder (macOS): opens Terminal and runs launch.sh
cd "$(dirname "$0")" || exit 1
./launch.sh
status=$?
if [ $status -ne 0 ]; then
    echo
    read -n 1 -s -r -p "Press any key to close..."
fi
exit $status
