#!/usr/bin/env bash
# NAME: Redis 健康
# UNIT: mixed
# Auto-discover redis-server instances; read requirepass from conf via REDISCLI_AUTH
set -u
count=0
for p in $(pgrep -x redis-server 2>/dev/null); do
  cmd=$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null)
  bin=$(echo "$cmd" | awk '{print $1}')
  port=$(echo "$cmd" | grep -oE '[0-9]+$')
  [ -n "$port" ] || port=$(echo "$cmd" | grep -oE ':[0-9]+' | head -1 | tr -d ':')
  [ -n "$port" ] || continue
  confarg=$(echo "$cmd" | grep -oE '/[^ ]+\.conf' | head -1)
  home=""; case "$bin" in /*) home=$(dirname "$(dirname "$bin")");; esac
  pass=""
  for c in "$confarg" "$home/conf/redis.conf" "$(dirname "$bin")/redis.conf" "/etc/redis/redis-$port.conf" "/etc/redis/redis.conf"; do
    [ -n "$c" ] && [ -r "$c" ] || continue
    pv=$(grep -E '^[[:space:]]*requirepass[[:space:]]+.' "$c" 2>/dev/null | head -1 | awk '{print $2}')
    [ -n "$pv" ] && { pass="$pv"; break; }
  done
  count=$((count+1))
  [ -n "$pass" ] && export REDISCLI_AUTH="$pass"
  info=$(timeout 5 redis-cli --no-auth-warning -p "$port" info 2>/dev/null | tr -d '\r')
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
      if(mm+0>0 && um!=""){printf("redis_%s_used_mem_pct=%.1f threshold=>90 warn=>80 unit=%%\n",P,um*100/mm); printf("redis_%s_mem=%s/%s\n",P,uh,mh)}
      else if(uh!=""){printf("redis_%s_mem=%s (maxmemory=unlimited)\n",P,uh)}
      tot=h+mi; if(tot>0){printf("redis_%s_hit_ratio=%.1f warn=<90 threshold=<70 unit=%%\n",P,h*100/tot)}
    }
  '
  [ -n "$pass" ] && unset REDISCLI_AUTH
done
echo "redis_instance_count=$count"
