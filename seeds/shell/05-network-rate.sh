#!/usr/bin/env bash
set -u
f1=$(mktemp); f2=$(mktemp)
trap 'rm -f "$f1" "$f2"' EXIT
snap() { awk -F'[: ]+' '/:/{if($1!="lo")print $1, $2, $10}' /proc/net/dev; }
snap > "$f1"
sleep 1
snap > "$f2"
awk 'NR==FNR{rx[$1]=$2;tx[$1]=$3;next}
     {printf "iface=%s rx_Bps=%d tx_Bps=%d\n", $1, $2-rx[$1], $3-tx[$1]}' "$f1" "$f2"
