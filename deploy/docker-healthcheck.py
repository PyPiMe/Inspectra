#!/usr/bin/env python3
"""容器健康检查：读 /data/config.yaml 的 port，请求根路径判 200。

Container healthcheck: read the port from /data/config.yaml and probe "/".
"""
import sys
import urllib.request

import yaml


def main() -> int:
    try:
        with open("/data/config.yaml", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}
        port = int(cfg.get("port", 8080))
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=4)
        return 0 if resp.status == 200 else 1
    except Exception:  # noqa: BLE001
        return 1


if __name__ == "__main__":
    sys.exit(main())
