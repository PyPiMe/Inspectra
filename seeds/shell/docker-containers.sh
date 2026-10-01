#!/usr/bin/env bash
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
