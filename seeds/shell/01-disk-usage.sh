#!/usr/bin/env bash
# 输出规范：精简、结构化 key=value
set -u
df -P -x tmpfs -x devtmpfs | awk 'NR>1 {
  gsub("%","",$5);
  printf "mount=%s used_pct=%s avail=%s\n", $6, $5, $4;
  if ($5+0 >= 90) printf "WARN: mount=%s usage=%s%%\n", $6, $5;
}'
