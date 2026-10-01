#!/usr/bin/env bash
# NAME: Nginx 检查(SSH)
# UNIT: mixed
# Generic host Nginx fallback: process / 80,443 listen / stub_status
procs=$(pgrep -x nginx 2>/dev/null | wc -l)
echo "nginx_proc=$procs threshold=<1 unit=count"
if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE ':(80|443)$'; then echo "nginx_listen=1 threshold=!=1 unit=bool"; else echo "nginx_listen=0 threshold=!=1 unit=bool"; fi
for url in http://127.0.0.1:8080/status http://127.0.0.1/status http://127.0.0.1/nginx_status; do
  if command -v curl >/dev/null 2>&1; then body=$(timeout 4 curl -s --max-time 3 "$url" 2>/dev/null)
  elif command -v python3 >/dev/null 2>&1; then body=$(timeout 4 python3 -c "import sys,urllib.request;sys.stdout.write(urllib.request.urlopen('$url',timeout=3).read().decode())" 2>/dev/null)
  else body=""; fi
  if [ -n "$body" ]; then
    active=$(echo "$body" | awk -F: '/Active connections/{gsub(/ /,"",$2);print $2}')
    echo "nginx_stub_status=1 threshold=!=1 unit=bool"
    [ -n "$active" ] && echo "nginx_active=$active unit=conn"
    break
  fi
done
