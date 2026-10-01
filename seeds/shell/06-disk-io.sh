#!/usr/bin/env bash
set -u
f1=$(mktemp); f2=$(mktemp)
trap 'rm -f "$f1" "$f2"' EXIT
snap() { awk '{if($3 ~ /^(sd|vd|nvme|dm-|md)/) print $3, $6, $10}' /proc/diskstats; }
snap > "$f1"
sleep 1
snap > "$f2"
awk 'NR==FNR{r[$1]=$2;w[$1]=$3;next}
     {printf "dev=%s read_Bps=%d write_Bps=%d\n", $1, ($2-r[$1])*512, ($3-w[$1])*512}' "$f1" "$f2"
