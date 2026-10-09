# Contributing

贡献指南

Thanks for helping improve Inspectra.

感谢你帮助改进 Inspectra。

## Development setup

开发环境

```bash
cp config.yaml.example config.yaml
cp secrets.env.example secrets.env
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
./venv/bin/python init.py
./venv/bin/python app.py
```

## Checks before a pull request

提交 PR 前的检查

- Python compiles: `python3 -m py_compile app.py engine.py i18n.py collectors.py model_client.py sanitize.py notify.py scheduler.py vault.py backup.py models.py init.py config.py chatbot.py applog.py`
- Python 可编译：`python3 -m py_compile app.py engine.py i18n.py collectors.py model_client.py sanitize.py notify.py scheduler.py vault.py backup.py models.py init.py config.py chatbot.py applog.py`
- Locale packs (`locales/zh-CN.json`, `locales/en.json`, `locales/_template.json`) must have identical key sets.
- 语言包（`locales/zh-CN.json`、`locales/en.json`、`locales/_template.json`）键集必须一致。
- All Jinja templates must parse.
- 所有 Jinja 模板必须可解析。
- These also run in CI (`.github/workflows/ci.yml`).
- 以上同样由 CI 执行（`.github/workflows/ci.yml`）。

## Commit messages

提交说明

- Use bilingual commit messages: one title line in the form `中文标题 / English title`, with the Chinese body before the English body.
- 使用中英双语提交说明：标题一行，格式 `中文标题 / English title`；正文中文段在前、英文段在后。
- Do not reference internal design/planning documents in commits.
- 提交信息中不要引用内部设计/规划文档。
- Desensitize: never commit real hostnames, IPs, credentials, tokens or passwords; use generic placeholders.
- 脱敏：切勿提交真实主机名、IP、凭据、token 或密码；请使用通用占位符。

## License

许可证

By contributing, you agree that your contributions are licensed under the Apache License 2.0 (see `LICENSE`).

贡献即表示你同意你的贡献以 Apache-2.0 许可证授权（见 `LICENSE`）。
