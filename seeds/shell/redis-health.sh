#!/usr/bin/env bash
# UNIT: mixed
# Auto-discover redis-server instances; resolve requirepass from common conf paths (incl. include);
# alive by listening port (ss/netstat), INFO metrics optional.
set -u

have() { command -v "$1" >/dev/null 2>&1; }

# 端口是否在监听（不依赖 redis-cli）
# Is the port listening (no redis-cli needed)
listen_has() {
  if have ss; then ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1$"
  elif have netstat; then netstat -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1$"
  else return 1; fi
}

# 从 conf 读取 requirepass（含 include 一层）
# Read requirepass from conf (one include level)
conf_pass() {
  f="$1"
  [ -n "$f" ] && [ -r "$f" ] || return 1
  pv=$(grep -E '^[[:space:]]*requirepass[[:space:]]+.' "$f" 2>/dev/null | head -1 | awk '{print $2}')
  if [ -n "$pv" ]; then echo "$pv"; return 0; fi
  for inc in $(grep -E '^[[:space:]]*include[[:space:]]+' "$f" 2>/dev/null | awk '{print $2}'); do
    [ -n "$inc" ] && [ -r "$inc" ] || continue
    pv=$(grep -E '^[[:space:]]*requirepass[[:space:]]+.' "$inc" 2>/dev/null | head -1 | awk '{print $2}')
    [ -n "$pv" ] && { echo "$pv"; return 0; }
  done
  return 1
}

count=0
for p in $(pgrep -x redis-server 2>/dev/null); do
  cmd=$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null)
  bin=$(echo "$cmd" | awk '{print $1}')
  home=""; case "$bin" in /*) home=$(dirname "$(dirname "$bin")");; esac
  confarg=$(echo "$cmd" | grep -oE '/[^ ]+\.conf' | head -1)

  # 端口：*:N / :N / --port N
  # Port: *:N / :N / --port N
  port=$(echo "$cmd" | grep -oE ':[0-9]+' | head -1 | tr -d ':')
  [ -n "$port" ] || port=$(echo "$cmd" | grep -oE '\-\-port[= ]+[0-9]+' | grep -oE '[0-9]+$')

  # requirepass：常见路径 + 进程 conf + 发行版默认（含 include）
  # requirepass: common paths + process conf + distro default (incl. include)
  pass=""
  for c in "$confarg" "$home/conf/redis.conf" "$home/etc/redis.conf" "$(dirname "$bin")/redis.conf" \
           "/etc/redis.conf" "/etc/redis/redis.conf" "/etc/redis/redis-${port}.conf" \
           "/usr/local/etc/redis.conf" "/usr/local/etc/redis/redis.conf"; do
    [ -n "$c" ] && [ -r "$c" ] || continue
    pv=$(conf_pass "$c") && { pass="$pv"; break; }
    [ -n "$port" ] || port=$(grep -E '^[[:space:]]*port[[:space:]]+[0-9]+' "$c" 2>/dev/null | head -1 | awk '{print $2}')
  done
  [ -n "$port" ] || port=6379
  count=$((count+1))

  # INFO（可选）：有 redis-cli 且能（带密码）取到才有指标
  # INFO (optional): only when redis-cli can fetch (with password)
  # 兼容旧版 redis-cli（如 3.2 不支持 --no-auth-warning / REDISCLI_AUTH），统一用 -a。
  # Compatible with old redis-cli (e.g. 3.2 lacks --no-auth-warning / REDISCLI_AUTH); always use -a.
  info=""
  if have redis-cli; then
    if [ -n "$pass" ]; then
      info=$(timeout 5 redis-cli -h 127.0.0.1 -p "$port" -a "$pass" info 2>/dev/null | tr -d '\r')
    else
      info=$(timeout 5 redis-cli -h 127.0.0.1 -p "$port" info 2>/dev/null | tr -d '\r')
    fi
  fi

  # 存活判定：以“端口在监听”为准（拿不到 INFO 不代表挂了）
  # Liveness by listening port (missing INFO does not mean down)
  if listen_has "$port"; then
    echo "redis_${port}_alive=1 threshold=!=1 unit=bool"
  elif [ -n "$info" ]; then
    echo "redis_${port}_alive=1 threshold=!=1 unit=bool"
  else
    echo "redis_${port}_alive=0 threshold=!=1 unit=bool"
  fi

  if [ -n "$info" ]; then
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
        if(mm+0>0 && um!=""){printf("redis_%s_used_mem_pct=%.1f threshold=>90 warn=>80 unit=%%\n",P,um*100/mm); printf("redis_%s_mem=%s/%s\n",P,uh,mh)}
        else if(uh!=""){printf("redis_%s_mem=%s\n",P,uh); printf("redis_%s_maxmemory=unlimited\n",P)}
        tot=h+mi; if(tot>0){printf("redis_%s_hit_ratio=%.1f warn=<90 threshold=<70 unit=%%\n",P,h*100/tot)}
      }
    '
  else
    echo "redis_${port}_info=unavailable"
  fi
done
echo "redis_instance_count=$count"
