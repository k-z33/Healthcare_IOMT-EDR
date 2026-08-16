#!/bin/bash
inotifywait -m -e create -e moved_to --format '%f' ~/forensics-tools/reports | while read fname; do
    [[ "$fname" == report_*.html ]] && sleep 2 && ~/forensics-tools/build_index.sh
done
