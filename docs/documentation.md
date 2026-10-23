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
python scripts/check_docs.py
python -m mkdocs serve --dev-addr 127.0.0.1:8000
~~~

修改 Markdown 后重新运行整理脚本。`mkdocs build --strict` 检查导航和链接，警告会导致构建失败。文档站支持中文搜索、代码复制、深浅主题和窄屏导航；不依赖 Google Fonts。

## GitHub Pages 发布

仓库设置 **Settings → Pages → Build and deployment → Source** 使用 **GitHub Actions**。首次启用需要仓库管理员操作；工作流不保存个人访问令牌。

`.github/workflows/docs.yml` 在文档相关文件更新时自动构建，PR 只校验，推送 `main` 或手动运行才发布。部署使用 `github-pages` 环境，仅部署任务拥有 `pages: write` 和 `id-token: write`。

公开站点预期地址为 `https://zwz211123.github.io/gatehouse/`。更换仓库名或绑定域名后，应同步修改 `mkdocs.yml` 的 `site_url`。文档站的 HTTPS 与实际堡垒机 Web 的 TLS 是两套独立配置。

## CI 注入文档版本

不需要为了更新网站逐页替换版本号。Release 工作流在发布成功后，把已校验的 `version` 输出传给 Documentation 可复用工作流。版本由 CI 注入，不再与源码中的固定产品版本比较；脚本通过 `packaging/versioning.py` 校验版本格式及正式/预发布渠道，并从本次检出的源码确定提交身份。

普通推送、PR 或独立手动构建使用统一构建身份解析：Git 工作树默认 `dev-<12位提交SHA>`，源码归档可恢复 `BUILD-INFO.json` 中的身份；没有这些信息时为 `dev`。独立文档构建标注“开发版 / 未发布”，Release 调用时标注正式版或预发布版。本站仍使用一个地址，展示最近一次成功部署的内容；开发版部署会替换之前的正式版页面，当前不建立多版本归档。

首页和开发产物路径使用 `docs_version` 变量，安装示例使用独立的 `download_version` 变量；源码模板以双花括号包围变量名。GitHub 原始 Markdown 中会显示占位符，以生成的网站或包内离线文档为完整阅读版本。升级历史、CHANGELOG、旧版迁移测试和工具链版本不会参与替换。

构建会查询 GitHub 最新正式 Release，并确认存在对应 amd64 bundle。开发版或预发布版的安装示例优先使用该已发布版本；尚无可用正式包时，会明确要求先自行构建，不声称下载文件已经存在。正式 Release 成功调用时，安装示例使用刚发布的版本。

本地默认按开发版构建；可以设置 `DOCS_VERSION` 和 `DOCS_CHANNEL` 来复现 CI 元数据（channel 为 `development`、`release` 或 `prerelease`）。正式/预发布渠道必须显式提供格式有效的 `DOCS_VERSION`，且版本后缀须与渠道匹配；无需修改 Go 源码中的版本默认值。本地不自动查询 GitHub；可将官方 Release API 返回值保存为 `build/latest-release.json` 复现下载版本选择，删除该文件则恢复“未确认发布包”的提示。CI 每次重新获取该文件，不复用旧结果。

`python scripts/test_docs.py` 覆盖版本格式与渠道校验、开发/正式/预发布状态、下载包选择、离线文档与历史版本保留。`python scripts/check_docs.py` 在构建后验证真实 HTML 中的版本字段、安装变量、首页按钮和本地链接。每次 CI 的 Summary 会显示本次文档版本、渠道及安装示例版本。

## 安装包内的离线文档

打包脚本使用同一版本替换函数生成 `build/package-docs/`，用于架构 bundle 和 Debian 组件包中的文档。离线文档的版本与安装示例都使用该包的构建身份，不查询最新 Release；预发布包也对应自身版本。生成结果保留 `docs/`、根目录 Markdown 和资源的原有相对路径，不使用网站专用的页面重命名与链接转换。

源码归档仍保留原始模板和文档构建脚本，以及 `BUILD-INFO.json`。从源码归档重建时重新渲染包内文档；不要把已经渲染的安装文档写回源码模板。历史版本记录继续保留。

如果 Release 已发布而文档阶段失败，可仅重跑失败的文档任务；不要重新创建相同标签的 Release。独立手动运行 Documentation 仍按开发版构建。
