#!/usr/bin/env bash
set -u
read -r _ u n s i w irq sirq st _ < /proc/stat
t1=$((u + n + s + i + w + irq + sirq + st)); idle1=$((i + w))
sleep 1
read -r _ u n s i w irq sirq st _ < /proc/stat
t2=$((u + n + s + i + w + irq + sirq + st)); idle2=$((i + w))
dt=$((t2 - t1)); di=$((idle2 - idle1))
if [ "$dt" -gt 0 ]; then
  used=$(( (dt - di) * 100 / dt ))
else
  used=0
fi
echo "cpu_used_pct=$used"
if [ "$used" -ge 90 ]; then echo "WARN: cpu usage=${used}%"; fi
