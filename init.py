#!/usr/bin/env python3
"""首次初始化：建库/生成 vault.key/示例脚本与 PromQL 模板/默认 settings。

- 幂等：已初始化则跳过不覆盖、补缺失项
- `--force` 重置（危险操作，需确认）
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import backup
import models
import sanitize
import vault
from config import get_config, set_config, load_config

SEED_SHELL = [
    {
        "name": "磁盘使用率",
        "filename": "01-disk-usage.sh",
        "desc": "输出各挂载点使用率（key=value），超 90% 标 WARN",
        "content": """#!/usr/bin/env bash
# 输出规范：精简、结构化 key=value
set -u
df -P -x tmpfs -x devtmpfs | awk 'NR>1 {
  gsub("%","",$5);
  printf "mount=%s used_pct=%s avail=%s\\n", $6, $5, $4;
  if ($5+0 >= 90) printf "WARN: mount=%s usage=%s%%\\n", $6, $5;
}'
""",
    },
    {
        "name": "内存与负载",
        "filename": "02-memory-load.sh",
        "desc": "输出内存使用率与 1/5/15 分钟负载",
        "content": """#!/usr/bin/env bash
set -u
read -r total avail <<<"$(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{print t, a}' /proc/meminfo)"
used_pct=$(( (total - avail) * 100 / total ))
read -r l1 l5 l15 _ < /proc/loadavg
echo "mem_total_kb=$total mem_avail_kb=$avail mem_used_pct=$used_pct"
echo "load1=$l1 load5=$l5 load15=$l15"
""",
    },
    {
        "name": "关键服务状态",
        "filename": "03-services.sh",
        "desc": "检查关键 systemd 服务是否 active",
        "content": """#!/usr/bin/env bash
set -u
SERVICES="sshd chronyd"
for s in $SERVICES; do
  state=$(systemctl is-active "$s" 2>/dev/null || true)
  echo "service=$s state=$state"
  [ "$state" = "active" ] || echo "ERROR: service=$s not active"
done
""",
    },
    {
        "name": "CPU 使用率(SSH)",
        "filename": "04-cpu-usage.sh",
        "desc": "基于 /proc/stat 1s 采样计算 CPU 使用率，>=90% 标 WARN",
        "content": """#!/usr/bin/env bash
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
""",
    },
    {
        "name": "网络流量速率",
        "filename": "05-network-rate.sh",
        "desc": "基于 /proc/net/dev 1s 采样，逐网卡 RX/TX 字节/秒（排除 lo）",
        "content": """#!/usr/bin/env bash
set -u
f1=$(mktemp); f2=$(mktemp)
trap 'rm -f "$f1" "$f2"' EXIT
snap() { awk -F'[: ]+' '/:/{if($1!="lo")print $1, $2, $10}' /proc/net/dev; }
snap > "$f1"
sleep 1
snap > "$f2"
awk 'NR==FNR{rx[$1]=$2;tx[$1]=$3;next}
     {printf "iface=%s rx_Bps=%d tx_Bps=%d\\n", $1, $2-rx[$1], $3-tx[$1]}' "$f1" "$f2"
""",
    },
    {
        "name": "磁盘 IO 速率",
        "filename": "06-disk-io.sh",
        "desc": "基于 /proc/diskstats 1s 采样，逐磁盘 读/写 字节/秒",
        "content": """#!/usr/bin/env bash
set -u
f1=$(mktemp); f2=$(mktemp)
trap 'rm -f "$f1" "$f2"' EXIT
snap() { awk '{if($3 ~ /^(sd|vd|nvme|dm-|md)/) print $3, $6, $10}' /proc/diskstats; }
snap > "$f1"
sleep 1
snap > "$f2"
awk 'NR==FNR{r[$1]=$2;w[$1]=$3;next}
     {printf "dev=%s read_Bps=%d write_Bps=%d\\n", $1, ($2-r[$1])*512, ($3-w[$1])*512}' "$f1" "$f2"
""",
    },
    {
        "name": "系统运行时长",
        "filename": "07-uptime.sh",
        "desc": "输出系统已运行秒数与空闲秒数",
        "content": """#!/usr/bin/env bash
set -u
read -r up idle < /proc/uptime
echo "uptime_seconds=${up%.*}"
echo "idle_seconds=${idle%.*}"
""",
    },
    {
        "name": "Java 进程检查",
        "filename": "java-process.sh",
        "desc": "通用检查：java 进程数量（为 0 FAIL）与总 RSS / Generic: java process count (0 => FAIL) and total RSS",
        "content": """#!/usr/bin/env bash
# NAME: Java 进程检查
# UNIT: mixed
# Generic: java process count (0 => FAIL) and total RSS
n=$(pgrep -x java 2>/dev/null | wc -l)
echo "java_proc_count=$n threshold=<1 unit=count"
rss=$(ps -C java -o rss= 2>/dev/null | awk '{s+=$1} END{print s+0}')
echo "java_rss_kb=$rss unit=KB"
""",
    },
    {
        "name": "VIP 归属",
        "filename": "vip-holder.sh",
        "desc": "反代节点：判断本机是否持有 VIP（master/backup），并检查 keepalived/nginx 服务；VIP 地址取自 keepalived 配置 / Reverse-proxy node: detect local VIP holder (master/backup) and check keepalived/nginx; VIP from keepalived config",
        "content": """#!/usr/bin/env bash
# NAME: VIP 归属
# UNIT: mixed
# Reverse-proxy node: detect local VIP holder (master/backup) and check keepalived/nginx services
conf=/etc/keepalived/keepalived.conf
vip=$(grep -A5 -i 'virtual_ipaddress' "$conf" 2>/dev/null | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' | head -1)
[ -n "$vip" ] || vip=$(grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' "$conf" 2>/dev/null | head -1)
present=0
[ -n "$vip" ] && present=$(ip -4 -o addr show 2>/dev/null | grep -c "$vip/")
role=backup; [ "$present" = "1" ] && role=master
echo "vip_conf_readable=$([ -r "$conf" ] && echo 1 || echo 0) unit=bool"
echo "vip_address=$vip"
echo "vip_present=$present unit=bool"
echo "node_role=$role"
echo "keepalived_active=$(systemctl is-active keepalived 2>/dev/null) threshold=!=active"
echo "nginx_active=$(systemctl is-active nginx 2>/dev/null) threshold=!=active"
""",
    },
    {
        "name": "Redis 健康",
        "filename": "redis-health.sh",
        "desc": "按进程自动发现本机 redis-server 实例：存活/role/内存占比/命中率/淘汰/阻塞/RDB/主从；密码取实例 conf 的 requirepass（REDISCLI_AUTH 传入） / Auto-discover local redis-server instances: alive/role/mem%/hit-ratio/evicted/blocked/RDB/replication; read requirepass from the instance conf (via REDISCLI_AUTH)",
        "content": """#!/usr/bin/env bash
# NAME: Redis 健康
# UNIT: mixed
# Auto-discover redis-server instances; read requirepass from conf via REDISCLI_AUTH
set -u
count=0
for p in $(pgrep -x redis-server 2>/dev/null); do
  cmd=$(tr '\\0' ' ' < /proc/$p/cmdline 2>/dev/null)
  bin=$(echo "$cmd" | awk '{print $1}')
  port=$(echo "$cmd" | grep -oE '[0-9]+$')
  [ -n "$port" ] || port=$(echo "$cmd" | grep -oE ':[0-9]+' | head -1 | tr -d ':')
  [ -n "$port" ] || continue
  confarg=$(echo "$cmd" | grep -oE '/[^ ]+\\.conf' | head -1)
  home=""; case "$bin" in /*) home=$(dirname "$(dirname "$bin")");; esac
  pass=""
  for c in "$confarg" "$home/conf/redis.conf" "$(dirname "$bin")/redis.conf" "/etc/redis/redis-$port.conf" "/etc/redis/redis.conf"; do
    [ -n "$c" ] && [ -r "$c" ] || continue
    pv=$(grep -E '^[[:space:]]*requirepass[[:space:]]+.' "$c" 2>/dev/null | head -1 | awk '{print $2}')
    [ -n "$pv" ] && { pass="$pv"; break; }
  done
  count=$((count+1))
  [ -n "$pass" ] && export REDISCLI_AUTH="$pass"
  info=$(timeout 5 redis-cli --no-auth-warning -p "$port" info 2>/dev/null | tr -d '\\r')
  if [ -z "$info" ]; then echo "redis_${port}_alive=0 threshold=!=1 unit=bool"; [ -n "$pass" ] && unset REDISCLI_AUTH; continue; fi
  echo "redis_${port}_alive=1 threshold=!=1 unit=bool"
  echo "$info" | awk -F: -v P="$port" '
    function emit(k,v,thr,warn,unit){ printf("redis_%s_%s=%s", P, k, v); if(thr!="")printf(" threshold=%s",thr); if(warn!="")printf(" warn=%s",warn); if(unit!="")printf(" unit=%s",unit); print "" }
    $1=="role"{emit("role",$2)}
    $1=="connected_clients"{emit("clients",$2)}
    $1=="blocked_clients"{emit("blocked",$2,"",">0","")}
    $1=="used_memory"{um=$2}
    $1=="maxmemory"{mm=$2}
    $1=="used_memory_human"{uh=$2}
    $1=="maxmemory_human"{mh=$2}
    $1=="mem_fragmentation_ratio"{emit("mem_frag",$2,"",">3","")}
    $1=="keyspace_hits"{h=$2}
    $1=="keyspace_misses"{mi=$2}
    $1=="rdb_last_bgsave_status"{emit("rdb_status",$2,"!=ok")}
    $1=="master_link_status"{emit("repl_status",$2,"!=up")}
    $1=="master_last_io_seconds_ago"{emit("repl_lag_s",$2,"",">10")}
    END{
      if(mm+0>0 && um!=""){printf("redis_%s_used_mem_pct=%.1f threshold=>90 warn=>80 unit=%%\\n",P,um*100/mm); printf("redis_%s_mem=%s/%s\\n",P,uh,mh)}
      else if(uh!=""){printf("redis_%s_mem=%s (maxmemory=unlimited)\\n",P,uh)}
      tot=h+mi; if(tot>0){printf("redis_%s_hit_ratio=%.1f warn=<90 threshold=<70 unit=%%\\n",P,h*100/tot)}
    }
  '
  [ -n "$pass" ] && unset REDISCLI_AUTH
done
echo "redis_instance_count=$count"
""",
    },    {
        "name": "Docker 容器检查",
        "filename": "docker-containers.sh",
        "desc": "只读检查 Docker 容器：运行/重启/健康；重启策略=always 的容器未运行则 FAIL（依赖 webops 的只读 sudo docker 授权） / Read-only Docker check: up/restarts/health; FAIL if a restart=always container is not running (needs webops read-only sudo docker)",
        "content": """#!/usr/bin/env bash
# NAME: Docker 容器检查
# UNIT: mixed
# 依赖：webops 对 docker 的只读 sudo 授权（ps / ps -a / inspect）
# Requires read-only sudo docker for webops (ps / ps -a / inspect)
sudo="sudo -n"
if ! $sudo /usr/bin/docker ps >/dev/null 2>&1; then
  echo "docker_available=0 threshold=!=1 unit=bool"
  exit 0
fi
echo "docker_available=1 threshold=!=1 unit=bool"
names=$($sudo /usr/bin/docker ps -a 2>/dev/null | awk 'NR>1 && NF{print $NF}')
running=0; total=0; always_total=0; always_up=0
for n in $names; do
  info=$($sudo /usr/bin/docker inspect "$n" --format '{{.State.Status}}|{{.RestartCount}}|{{.HostConfig.RestartPolicy.Name}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>/dev/null)
  [ -n "$info" ] || continue
  total=$((total+1))
  status=$(echo "$info" | cut -d'|' -f1)
  restarts=$(echo "$info" | cut -d'|' -f2)
  policy=$(echo "$info" | cut -d'|' -f3)
  health=$(echo "$info" | cut -d'|' -f4)
  [ "$status" = "running" ] && running=$((running+1))
  if [ "$policy" = "always" ]; then
    always_total=$((always_total+1))
    up=0; [ "$status" = "running" ] && up=1
    [ "$up" = "1" ] && always_up=$((always_up+1))
    echo "docker_${n}_up=$up threshold=!=1 unit=bool"
    echo "docker_${n}_restarts=$restarts unit=times warn=>5"
    [ "$health" != "none" ] && echo "docker_${n}_health=$health"
  fi
done
echo "docker_running=$running unit=count"
echo "docker_total=$total unit=count"
echo "docker_always_total=$always_total unit=count"
echo "docker_always_up=$always_up unit=count"
""",
    },
    {
        "name": "Nginx 检查(SSH)",
        "filename": "nginx-check.sh",
        "desc": "通用主机 Nginx 兜底：进程、80/443 监听、stub_status（不依赖 systemd/nginx CLI） / Generic host Nginx fallback: process, 80/443 listen, stub_status (no systemd/nginx CLI)",
        "content": """#!/usr/bin/env bash
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
""",
    },
]

SEED_PROMQL = [
    {
        "name": "磁盘使用率",
        "filename": "disk-usage.promql",
        "desc": "非 tmpfs/overlay 文件系统使用率，超 90% FAIL",
        "content": """# NAME: 磁盘使用率
# MODE: instant
# THRESHOLD: >90
# UNIT: %
100 - (node_filesystem_avail_bytes{fstype!~"tmpfs|overlay",$instance} / node_filesystem_size_bytes{fstype!~"tmpfs|overlay",$instance} * 100)
""",
    },
    {
        "name": "内存使用率",
        "filename": "memory-usage.promql",
        "desc": "内存使用率，超 90% FAIL",
        "content": """# NAME: 内存使用率
# MODE: instant
# THRESHOLD: >90
# UNIT: %
(1 - node_memory_MemAvailable_bytes{$instance} / node_memory_MemTotal_bytes{$instance}) * 100
""",
    },
    {
        "name": "CPU 使用率",
        "filename": "cpu-usage.promql",
        "desc": "5m 平均 CPU 使用率，超 90% FAIL",
        "content": """# NAME: CPU 使用率
# MODE: instant
# THRESHOLD: >90
# UNIT: %
100 - (avg by(instance)(rate(node_cpu_seconds_total{mode="idle",$instance}[5m])) * 100)
""",
    },
    {
        "name": "系统负载(1m)",
        "filename": "load1.promql",
        "desc": "1 分钟平均负载（仅展示，不设阈值）",
        "content": """# NAME: 系统负载(1m)
# MODE: instant
# UNIT: load
node_load1{$instance}
""",
    },
    {
        "name": "运行时长",
        "filename": "uptime.promql",
        "desc": "系统已运行秒数",
        "content": """# NAME: 运行时长
# MODE: instant
# UNIT: s
time() - node_boot_time_seconds{$instance}
""",
    },
    {
        "name": "失败服务数",
        "filename": "failed-services.promql",
        "desc": "处于 failed 状态的 systemd 单元数，>0 FAIL",
        "content": """# NAME: 失败服务数
# MODE: instant
# THRESHOLD: >0
# UNIT: count
count(node_systemd_unit_state{state="failed",$instance} == 1)
""",
    },
    {
        "name": "磁盘写入速率",
        "filename": "disk-write-rate.promql",
        "desc": "5m 区间磁盘写入字节/秒（range 示例）",
        "content": """# NAME: 磁盘写入速率
# MODE: range
# WINDOW: 5m
# STEP: 1m
# UNIT: B/s
rate(node_disk_written_bytes_total{$instance}[5m])
""",
    },
    # ---- 通用 ----
    {
        "name": "目标存活(up)",
        "filename": "up.promql",
        "desc": "该实例所有抓取任务存活（任一 job down 即 FAIL）",
        "content": """# NAME: 目标存活(up)
# MODE: instant
# THRESHOLD: <1
# UNIT: bool
up{$instance}
""",
    },
    # ---- Proxmox VE（pve-exporter）----
    {
        "name": "PVE 节点存活",
        "filename": "pve-node-up.promql",
        "desc": "PVE 各节点在线状态",
        "content": """# NAME: PVE 节点存活
# MODE: instant
# THRESHOLD: <1
# UNIT: bool
pve_up{id=~"node/.*",$instance}
""",
    },
    {
        "name": "PVE 集群存活",
        "filename": "pve-cluster-up.promql",
        "desc": "PVE 集群在线状态",
        "content": """# NAME: PVE 集群存活
# MODE: instant
# THRESHOLD: <1
# UNIT: bool
pve_up{id=~"cluster/.*",$instance}
""",
    },
    {
        "name": "PVE 节点 CPU 使用率",
        "filename": "pve-node-cpu.promql",
        "desc": "PVE 节点 CPU 使用率，超 90% FAIL",
        "content": """# NAME: PVE 节点 CPU 使用率
# MODE: instant
# THRESHOLD: >90
# UNIT: %
pve_cpu_usage_ratio{id=~"node/.*",$instance} * 100
""",
    },
    {
        "name": "PVE 节点内存使用率",
        "filename": "pve-node-memory.promql",
        "desc": "PVE 节点内存使用率，超 90% FAIL",
        "content": """# NAME: PVE 节点内存使用率
# MODE: instant
# THRESHOLD: >90
# UNIT: %
pve_memory_usage_bytes{id=~"node/.*",$instance} / pve_memory_size_bytes{id=~"node/.*",$instance} * 100
""",
    },
    {
        "name": "PVE 节点磁盘使用率",
        "filename": "pve-node-disk.promql",
        "desc": "PVE 节点根盘使用率，超 90% FAIL",
        "content": """# NAME: PVE 节点磁盘使用率
# MODE: instant
# THRESHOLD: >90
# UNIT: %
pve_disk_usage_bytes{id=~"node/.*",$instance} / pve_disk_size_bytes{id=~"node/.*",$instance} * 100
""",
    },
    {
        "name": "PVE 存储池使用率",
        "filename": "pve-storage-usage.promql",
        "desc": "PVE 各存储池使用率，超 90% FAIL",
        "content": """# NAME: PVE 存储池使用率
# MODE: instant
# THRESHOLD: >90
# UNIT: %
pve_disk_usage_bytes{id=~"storage/.*",$instance} / pve_disk_size_bytes{id=~"storage/.*",$instance} * 100
""",
    },
    {
        "name": "PVE 节点运行时长",
        "filename": "pve-node-uptime.promql",
        "desc": "PVE 节点最短运行时长（秒）",
        "content": """# NAME: PVE 节点运行时长
# MODE: instant
# UNIT: s
min(pve_uptime_seconds{id=~"node/.*",$instance})
""",
    },
    {
        "name": "PVE 未备份虚拟机数",
        "filename": "pve-not-backed-up.promql",
        "desc": "超过备份周期的虚拟机数量，>0 FAIL",
        "content": """# NAME: PVE 未备份虚拟机数
# MODE: instant
# THRESHOLD: >0
# UNIT: count
max(pve_not_backed_up_total{$instance})
""",
    },
    {
        "name": "PVE HA 故障转移(fence)",
        "filename": "pve-ha-fence.promql",
        "desc": "存在 fence 状态的 HA 资源时 FAIL",
        "content": """# NAME: PVE HA 故障转移(fence)
# MODE: instant
# THRESHOLD: >0
# UNIT: count
sum(pve_ha_state{state="fence",$instance})
""",
    },
    {
        "name": "PVE 订阅异常",
        "filename": "pve-subscription.promql",
        "desc": "订阅 invalid/expired/suspended 时 FAIL（不含 notfound/new）",
        "content": """# NAME: PVE 订阅异常
# MODE: instant
# THRESHOLD: >0
# UNIT: count
sum(pve_subscription_status{status=~"invalid|expired|suspended",$instance})
""",
    },
    {
        "name": "PVE 网络入站速率",
        "filename": "pve-net-in.promql",
        "desc": "该实例上所有虚拟机/容器 5m 入站速率（B/s，仅展示）",
        "content": """# NAME: PVE 网络入站速率
# MODE: instant
# UNIT: B/s
sum(rate(pve_network_receive_bytes_total{id=~"qemu/.*|lxc/.*",$instance}[5m]))
""",
    },
    {
        "name": "PVE 网络出站速率",
        "filename": "pve-net-out.promql",
        "desc": "该实例上所有虚拟机/容器 5m 出站速率（B/s，仅展示）",
        "content": """# NAME: PVE 网络出站速率
# MODE: instant
# UNIT: B/s
sum(rate(pve_network_transmit_bytes_total{id=~"qemu/.*|lxc/.*",$instance}[5m]))
""",
    },
    # ---- Proxmox VE 单虚拟机（需服务器填「虚拟化标识」，脚本用 $guest）----
    {
        "name": "PVE 虚拟机 CPU 使用率",
        "filename": "pve-vm-cpu.promql",
        "desc": "指定虚拟机 CPU 使用率，超 90% FAIL（需服务器填虚拟化标识）",
        "content": """# NAME: PVE 虚拟机 CPU 使用率
# MODE: instant
# THRESHOLD: >90
# UNIT: %
max by (id)(pve_cpu_usage_ratio{$guest}) * 100
""",
    },
    {
        "name": "PVE 虚拟机内存使用率",
        "filename": "pve-vm-memory.promql",
        "desc": "指定虚拟机内存使用率，超 90% FAIL",
        "content": """# NAME: PVE 虚拟机内存使用率
# MODE: instant
# UNIT: %
# DISPLAY: true
# PVE 内存=total-free，把 page cache 计入已用，会系统性虚高；真实内存请以 OS(SSH) 为准。
# PVE guest memory = total-free (counts page cache as used) and is unreliable; prefer OS/SSH memory.
max by (id)(pve_memory_usage_bytes{$guest}) / max by (id)(pve_memory_size_bytes{$guest}) * 100
""",
    },
    {
        "name": "PVE 虚拟机网络入站速率",
        "filename": "pve-vm-net-in.promql",
        "desc": "指定虚拟机 5m 入站速率（B/s，仅展示）",
        "content": """# NAME: PVE 虚拟机网络入站速率
# MODE: instant
# UNIT: B/s
max by (id)(rate(pve_network_receive_bytes_total{$guest}[5m]))
""",
    },
    {
        "name": "PVE 虚拟机网络出站速率",
        "filename": "pve-vm-net-out.promql",
        "desc": "指定虚拟机 5m 出站速率（B/s，仅展示）",
        "content": """# NAME: PVE 虚拟机网络出站速率
# MODE: instant
# UNIT: B/s
max by (id)(rate(pve_network_transmit_bytes_total{$guest}[5m]))
""",
    },
    {
        "name": "PVE 虚拟机磁盘写入速率",
        "filename": "pve-vm-disk-write.promql",
        "desc": "指定虚拟机 5m 磁盘写入速率（B/s，仅展示）",
        "content": """# NAME: PVE 虚拟机磁盘写入速率
# MODE: instant
# UNIT: B/s
max by (id)(rate(pve_disk_written_bytes_total{$guest}[5m]))
""",
    },
    {
        "name": "PVE 虚拟机运行时长",
        "filename": "pve-vm-uptime.promql",
        "desc": "指定虚拟机运行时长（秒）",
        "content": """# NAME: PVE 虚拟机运行时长
# MODE: instant
# UNIT: s
max by (id)(pve_uptime_seconds{$guest})
""",
    },
    {
        "name": "PVE 虚拟机 HA 状态",
        "filename": "pve-vm-ha.promql",
        "desc": "指定虚拟机 HA 未处于 started 时 FAIL",
        "content": """# NAME: PVE 虚拟机 HA 状态
# MODE: instant
# THRESHOLD: <1
# UNIT: bool
max by (id)(pve_ha_state{state="started",$guest})
""",
    },
    # ---- Nginx ----
    {
        "name": "Nginx 存活",
        "filename": "nginx-up.promql",
        "desc": "nginx-exporter 在线状态",
        "content": """# NAME: Nginx 存活
# MODE: instant
# THRESHOLD: <1
# UNIT: bool
nginx_up{$instance}
""",
    },
    {
        "name": "Nginx 概览",
        "filename": "nginx-overview.promql",
        "desc": "Nginx 汇总：up/活跃/读写等待连接/累计请求与连接/QPS/新建连接速率",
        "content": """# NAME: Nginx 概览
# MODE: instant
# UNIT: mixed
# DISPLAY: true
# Info-only: nginx overview panel
label_replace(nginx_up{$instance}, "item", "存活(1=正常)", "__name__", ".*")
or label_replace(nginx_connections_active{$instance}, "item", "活跃连接", "__name__", ".*")
or label_replace(nginx_connections_reading{$instance}, "item", "读取中连接", "__name__", ".*")
or label_replace(nginx_connections_writing{$instance}, "item", "写入中连接", "__name__", ".*")
or label_replace(nginx_connections_waiting{$instance}, "item", "等待连接", "__name__", ".*")
or label_replace(nginx_connections_accepted{$instance}, "item", "累计接受连接", "__name__", ".*")
or label_replace(nginx_connections_handled{$instance}, "item", "累计处理连接", "__name__", ".*")
or label_replace(nginx_http_requests_total{$instance}, "item", "累计请求数", "__name__", ".*")
""",
    },
    {
        "name": "Nginx QPS",
        "filename": "nginx-qps.promql",
        "desc": "Nginx 5m 平均 QPS，超阈值 FAIL（默认 >100，可改）",
        "content": """# NAME: Nginx QPS
# MODE: instant
# THRESHOLD: >100
# UNIT: req/s
sum by (instance)(rate(nginx_http_requests_total{$instance}[5m]))
""",
    },
    {
        "name": "Nginx 新建连接速率",
        "filename": "nginx-conn-rate.promql",
        "desc": "Nginx 5m 新建连接速率，超阈值 FAIL（默认 >100，可改）",
        "content": """# NAME: Nginx 新建连接速率
# MODE: instant
# THRESHOLD: >100
# UNIT: conn/s
sum by (instance)(rate(nginx_connections_accepted{$instance}[5m]))
""",
    },
    {
        "name": "Nginx 活跃连接数",
        "filename": "nginx-active-threshold.promql",
        "desc": "Nginx 当前活跃连接数，超阈值 FAIL（默认 >500，可改）",
        "content": """# NAME: Nginx 活跃连接数
# MODE: instant
# WARN: >800
# THRESHOLD: >1000
# UNIT: conn
nginx_connections_active{$instance}
""",
    },
    # ---- Keepalived ----
    {
        "name": "Keepalived 存活",
        "filename": "keepalived-up.promql",
        "desc": "keepalived-exporter 在线状态",
        "content": """# NAME: Keepalived 存活
# MODE: instant
# THRESHOLD: <1
# UNIT: bool
keepalived_up{$instance}
""",
    },
    {
        "name": "Keepalived 脚本检查",
        "filename": "keepalived-script.promql",
        "desc": "健康检查脚本状态，<1 FAIL",
        "content": """# NAME: Keepalived 脚本检查
# MODE: instant
# THRESHOLD: <1
# UNIT: bool
min by (name)(keepalived_script_status{$instance})
""",
    },
    # ---- HTTP 站点探活 ----
    {
        "name": "HTTP 站点可用",
        "filename": "http-status-up.promql",
        "desc": "http_status 探活：需把绑定 prom_instance 设为站点 URL（如 https://example.com）",
        "content": """# NAME: HTTP 站点可用
# MODE: instant
# THRESHOLD: <1
# UNIT: bool
up{job="http_status",$instance}
""",
    },
    # ---- Anubis ----
    {
        "name": "Anubis 代理请求速率",
        "filename": "anubis-proxy-rate.promql",
        "desc": "Anubis 代理请求 5m 速率（req/s，仅展示）",
        "content": """# NAME: Anubis 代理请求速率
# MODE: instant
# UNIT: req/s
sum(rate(anubis_proxied_requests_total{$instance}[5m]))
""",
    },
    # ---- VictoriaLogs ----
    {
        "name": "VictoriaLogs 磁盘使用率",
        "filename": "victorialogs-disk.promql",
        "desc": "VictoriaLogs 数据占用/总磁盘，超 90% FAIL",
        "content": """# NAME: VictoriaLogs 磁盘使用率
# MODE: instant
# THRESHOLD: >90
# UNIT: %
sum(vl_data_size_bytes{$instance}) / sum(vl_total_disk_space_bytes{$instance}) * 100
""",
    },
    {
        "name": "Keepalived 概览",
        "filename": "keepalived-overview.promql",
        "desc": "Keepalived 服务/VRRP 状态/健康检查脚本（信息展示，不判定） / Info-only: keepalived up / VRRP state / script status",
        "content": """# NAME: Keepalived 概览
# MODE: instant
# UNIT: mixed
# DISPLAY: true
# Info-only: keepalived up / VRRP state / script status
label_replace(keepalived_up{$instance}, "item", "Keepalived存活", "job", ".*")
or label_replace(keepalived_vrrp_state{$instance}, "item", "VRRP状态(2=MASTER)", "iname", ".*")
or label_replace(keepalived_script_status{$instance}, "item", "健康检查", "name", ".*")
""",
    },
    {
        "name": "Keepalived 主备",
        "filename": "keepalived-master.promql",
        "desc": "全集群 MASTER 数量（0 表示 VIP 无人持有），<1 FAIL；建议绑定到 VIP（不依赖 $instance） / Cluster MASTER count (0 = VIP not held); <1 FAIL; bind to VIP",
        "content": """# NAME: Keepalived 主备
# MODE: instant
# THRESHOLD: <1
# UNIT: count
# Cluster MASTER count; <1 FAIL; bind to VIP
label_replace(count(keepalived_vrrp_state{job="keepalived"} == 2), "item", "master_count", "job", ".*")
""",
    },
]


def _seed_scripts(force: bool = False) -> int:
    created = 0
    existing = {s["name"]: s for s in models.fetch_all("scripts")}
    for item in SEED_SHELL + SEED_PROMQL:
        kind = "promql" if item["filename"].endswith(".promql") else "shell"
        if item["name"] in existing:
            if not force:
                continue
            script = existing[item["name"]]
            backup.write_script(script, item["content"])
            continue
        with models.db() as conn:
            sid = models.insert(
                conn,
                "scripts",
                {
                    "name": item["name"],
                    "filename": item["filename"],
                    "kind": kind,
                    "desc": item["desc"],
                    "created_at": models.utcnow(),
                    "updated_at": models.utcnow(),
                },
            )
            backup.record(conn, "script", sid, "create", {"id": sid, "name": item["name"], "kind": kind, "content": item["content"]})
        script = {"id": sid, "kind": kind}
        backup.write_script(script, item["content"])
        existing[item["name"]] = {"id": sid, "kind": kind}  # 同一次运行内也去重，避免重名重复创建
        created += 1
    return created


def _seed_settings(force: bool = False) -> int:
    changed = 0
    with models.db() as conn:
        current = models.get_settings(conn)
        for key, value in models.DEFAULT_SETTINGS.items():
            if key == "sanitize_rules" and not value:
                value = json.dumps(sanitize.default_rules(), ensure_ascii=False)
            if key not in current or force:
                if current.get(key) != value:
                    models.set_setting(conn, key, value)
                    changed += 1
    return changed


def reset() -> None:
    """危险操作：清空所有数据表并删除脚本文件。"""
    conn = models.connect()
    try:
        for table in (
            "server_datasources",
            "servers",
            "groups",
            "scripts",
            "datasources",
            "models",
            "notifications",
            "run_schedule",
            "run_history",
            "audit_log",
            "backup_versions",
            "vault_entries",
            "settings",
        ):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
    finally:
        conn.close()
    cfg = get_config()
    if os.path.isdir(cfg.scripts_dir):
        for name in os.listdir(cfg.scripts_dir):
            if name.endswith((".sh", ".promql")):
                try:
                    os.remove(os.path.join(cfg.scripts_dir, name))
                except OSError:
                    pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PyPiMeOps 初始化")
    parser.add_argument("--config", default=None, help="config.yaml 路径（默认 ./config.yaml）")
    parser.add_argument("--force", action="store_true", help="重置并重建（危险）")
    parser.add_argument("-y", "--yes", action="store_true", help="跳过确认")
    args = parser.parse_args(argv)

    try:
        cfg = load_config(args.config)
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2
    set_config(cfg)
    models.set_db_path(cfg.db_path)
    cfg.ensure_dirs()
    models.init_db()
    vault.ensure_key()

    if args.force:
        if not args.yes:
            answer = input("--force 将清空所有数据与脚本文件，确认？[y/N] ").strip().lower()
            if answer not in ("y", "yes"):
                print("已取消")
                return 1
        reset()

    seeded = _seed_scripts(force=args.force)
    changed = _seed_settings(force=args.force)
    print(f"[OK] 数据库：{cfg.db_path}")
    print(f"[OK] vault.key：{cfg.vault_key_path}")
    print(f"[OK] 新增示例脚本：{seeded} 个；settings 变更：{changed} 项")
    print("提示：如需巡检，请依次在 Web 页面录入 凭据/服务器/数据源/模型/通知 并绑定脚本。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
