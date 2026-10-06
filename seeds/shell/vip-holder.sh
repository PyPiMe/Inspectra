#!/usr/bin/env bash
# UNIT: mixed
# Reverse-proxy node: detect local VIP holder (master/backup) and check keepalived/nginx services
conf=/etc/keepalived/keepalived.conf
vip=$(grep -A5 -i 'virtual_ipaddress' "$conf" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
[ -n "$vip" ] || vip=$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$conf" 2>/dev/null | head -1)
present=0
[ -n "$vip" ] && present=$(ip -4 -o addr show 2>/dev/null | grep -c "$vip/")
role=backup; [ "$present" = "1" ] && role=master
echo "vip_conf_readable=$([ -r "$conf" ] && echo 1 || echo 0) unit=bool"
echo "vip_address=$vip"
echo "vip_present=$present unit=bool"
echo "node_role=$role"
echo "keepalived_active=$(systemctl is-active keepalived 2>/dev/null) threshold=!=active"
echo "nginx_active=$(systemctl is-active nginx 2>/dev/null) threshold=!=active"
