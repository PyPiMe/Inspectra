#!/usr/bin/env bash
set -u
read -r up idle < /proc/uptime
echo "uptime_seconds=${up%.*}"
echo "idle_seconds=${idle%.*}"
