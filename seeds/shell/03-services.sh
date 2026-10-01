#!/usr/bin/env bash
set -u
SERVICES="sshd chronyd"
for s in $SERVICES; do
  state=$(systemctl is-active "$s" 2>/dev/null || true)
  echo "service=$s state=$state"
  [ "$state" = "active" ] || echo "ERROR: service=$s not active"
done
