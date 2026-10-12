#!/usr/bin/env bash
# Crypton - doppio clic da Finder (macOS): apre Terminal ed esegue launch.sh
cd "$(dirname "$0")" || exit 1
./launch.sh
status=$?
if [ $status -ne 0 ]; then
    echo
    read -n 1 -s -r -p "Premi un tasto per chiudere..."
fi
exit $status
