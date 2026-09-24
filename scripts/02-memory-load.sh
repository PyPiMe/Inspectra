#!/usr/bin/env bash
set -u
read -r total avail <<<"$(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{print t, a}' /proc/meminfo)"
used_pct=$(( (total - avail) * 100 / total ))
read -r l1 l5 l15 _ < /proc/loadavg
echo "mem_total_kb=$total mem_avail_kb=$avail mem_used_pct=$used_pct"
echo "load1=$l1 load5=$l5 load15=$l15"
