# Third-Party Notices

第三方许可声明

PyPiMeOps is licensed under the Apache License 2.0 (see [`LICENSE`](LICENSE)).
This file lists the third-party components it uses and their licenses. When you
redistribute PyPiMeOps (source or a deployed bundle), keep this file and the
third-party copyright/license notices.

PyPiMeOps 以 Apache-2.0 发布（见 [`LICENSE`](LICENSE)）。本文件列出其使用的第三方
组件及许可；**分发（源码或部署包）时请一并保留本文件与各组件版权/许可声明**。

## Python runtime dependencies

Python 运行时依赖

License identifiers follow the projects' own metadata. Copyright holders are the
respective projects/authors.

| Package | Version | License | Copyright / Project |
|---|---|---|---|
| Flask | 3.0.3 | BSD-3-Clause | Pallets |
| markupsafe | 2.1.5 | BSD-3-Clause | Pallets |
| requests | 2.32.3 | Apache-2.0 | Kenneth Reitz / Python Software Foundation |
| PyYAML | 6.0.2 | MIT | Kirill Simonov / PyYAML contributors |
| cryptography | 43.0.1 | Apache-2.0 OR BSD-3-Clause | Python Cryptographic Authority |
| markdown-it-py | 3.0.0 | MIT | Executable Book Project |
| **paramiko** | 3.4.0 | **LGPL-2.1** | Paramiko contributors (Jeff Forcier et al.) |

### Note on paramiko (LGPL-2.1)

关于 paramiko（LGPL-2.1）

`paramiko` is used **as an unmodified library** (imported at runtime), not copied
or modified into this project. Under LGPL-2.1 this is permitted; redistribution
must retain the LGPL notice and allow replacement of the library. Source and the
full LGPL-2.1 text: <https://github.com/paramiko/paramiko> (see `LICENSE` in that
repository).

`paramiko` 仅作为**未经修改的库**被运行时导入使用（非并入本项目源码），符合 LGPL-2.1；
再分发时须保留其 LGPL 声明并允许替换该库。

> Transitive dependencies of the above packages (e.g. `bcrypt`, `pynacl`,
> `jinja2`, `werkzeug`, `click`, `urllib3`, `certifi`, `cffi`) carry their own
> licenses; consult the installed distributions' metadata when bundling.

## Frontend assets (vendored, offline)

前端内置资源（离线）

| Component | Version | License | Copyright |
|---|---|---|---|
| Bootstrap (`web/static/vendor/bootstrap.min.css`, `bootstrap.bundle.min.js`) | 5.3.3 | MIT | Copyright 2011-2024 The Bootstrap Authors |

Bootstrap is vendored locally (no CDN). Its MIT copyright header is retained at
the top of both files under `web/static/vendor/`; do not remove it.

Bootstrap 本地内置（不走 CDN），其 MIT 版权声明保留在 `web/static/vendor/` 两文件
头部，请勿移除。

## How dependency licenses are tracked

依赖许可跟踪

- `requirements.txt` annotates each direct dependency's license.
- This file is the canonical third-party notice; keep it in sync when
  dependencies change.
