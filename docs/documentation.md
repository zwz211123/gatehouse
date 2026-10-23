# 文档站维护

文档使用 MkDocs Material 构建，发布到 GitHub Pages。中文 Markdown 保留在仓库中，网站构建不修改应用程序或实例数据。

## 内容位置

- 用户指南放在 `docs/`，导航在根目录 `mkdocs.yml`。
- 架构、升级、安全、测试状态等继续维护根目录的对应 Markdown。
- `scripts/prepare_docs.py` 将这些公开文档整理到 `build/docs-source/`，修正站内链接；代码文件链接指向 GitHub。
- `build/docs-site/` 为最终静态网站，不提交生成文件。

根目录文档无需复制到 `docs/` 再维护一份。新增根目录页面时，在脚本 `ROOT_PAGES` 和 `mkdocs.yml` 中登记；新增 `docs/` 页面会自动进入构建，但仍应添加导航入口。

## 本地构建与预览

在仓库根目录执行：

~~~bash
python3 -m venv .venv-docs
. .venv-docs/bin/activate
python -m pip install -r requirements-docs.txt
python scripts/prepare_docs.py
python -m mkdocs build --strict
python -m mkdocs serve --dev-addr 127.0.0.1:8000
~~~

修改 Markdown 后重新运行整理脚本。`mkdocs build --strict` 检查导航和链接，警告会导致构建失败。文档站支持中文搜索、代码复制、深浅主题和窄屏导航；不依赖 Google Fonts。

## GitHub Pages 发布

仓库设置 **Settings → Pages → Build and deployment → Source** 使用 **GitHub Actions**。首次启用需要仓库管理员操作；工作流不保存个人访问令牌。

`.github/workflows/docs.yml` 在文档相关文件更新时自动构建，PR 只校验，推送 `main` 或手动运行才发布。部署使用 `github-pages` 环境，仅部署任务拥有 `pages: write` 和 `id-token: write`。

公开站点预期地址为 `https://zwz211123.github.io/gatehouse/`。更换仓库名或绑定域名后，应同步修改 `mkdocs.yml` 的 `site_url`。文档站的 HTTPS 与实际堡垒机 Web 的 TLS 是两套独立配置。
