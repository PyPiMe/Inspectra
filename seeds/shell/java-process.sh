#!/usr/bin/env bash
# UNIT: mixed
# Generic: java process count (0 => FAIL) and total RSS
n=$(pgrep -x java 2>/dev/null | wc -l)
echo "java_proc_count=$n threshold=<1 unit=count"
rss=$(ps -C java -o rss= 2>/dev/null | awk '{s+=$1} END{print s+0}')
echo "java_rss_kb=$rss unit=KB"
