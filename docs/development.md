# 开发与构建

## 环境

- Linux；Go 最低版本见 `go.mod`，当前项目检查使用 Go 1.27.3。
- Python 3、`dpkg-deb`、xz、binutils，用于构建和检查 Debian 包。
- OpenSSH 客户端、现代 SCP、sshpass、OpenSSL，用于集成测试。
- Node.js 24 与 npm，仅用于 Web DOM 测试，生产运行和编译静态前端不需要 Node。
- qemu-aarch64-static，用于在 amd64 主机运行 arm64 测试程序及包内 CLI。

Debian 类开发机可按需要安装：

~~~bash
sudo apt-get update
sudo apt-get install python3 dpkg-dev xz-utils binutils openssh-client sshpass openssl qemu-user-static
~~~

Go 和 Node 应独立准备符合要求的版本，不假设发行版仓库默认版本足够新。

## 常用检查

~~~bash
go mod download
go test -race ./...
go vet ./...
npm ci
npm run test:web
~~~

系统 OpenSSH/SCP 用例需要 sshpass 在 PATH 中；检查输出有无 skip，不将未执行的外部客户端测试算成通过。DOM 测试不是浏览器视觉或辅助技术验收。

## 编译四个角色

~~~bash
mkdir -p build/process
for role in core ssh web cli; do
  name="ghb-$role"
  if [ "$role" = cli ]; then name=ghbctl; fi
  CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags "-X main.role=$role" \
    -o "build/process/$name" ./cmd/gatehouse
done
~~~

CLI 的默认角色为 cli；服务程序必须用对应角色构建，不能简单复制一个 CLI 文件作为服务。

## 构建身份

产品版本由构建流程注入，不从配置文件或联网查询获得。手动 Release 的标签输入是发布版本的唯一来源，工作流将同一版本传给构建和文档；提交 SHA 固定为本次工作流检出的提交。

普通 CI 和 Git 工作树打包默认生成 `dev-<12位提交SHA>`，Debian 包版本为 `0~dev.<SHA>`；无 Git 且无构建元数据时为 `dev`。直接 `go build` 的默认身份是 `dev` / `unknown`。`ghbctl version` 保持输出纯版本，`ghbctl version --json` 返回版本和完整提交 SHA。

源码包自动携带 `BUILD-INFO.json`，无 `.git` 时由打包脚本恢复原版本和提交。`build/version.json` 记录本次构建身份；仅重打包必须与已有二进制的身份一致。数据库 schema 版本独立维护。

## Debian 包

~~~bash
GATEHOUSE_GO=go python3 packaging/build.py
GHB_QEMU=/usr/bin/qemu-aarch64-static python3 tests/packages.py
~~~

产物位于 `dist/{{ docs_version }}/`（普通开发构建以实际 `build/version.json` 为准）：8 个架构组件 deb、1 个元包、每架构 bundle、源码归档及 SHA-256 清单。amd64 使用通用 `GOAMD64=v1`，两个架构均 `CGO_ENABLED=0`。构建不安装包，不修改宿主机服务。

可在本地通过 `GATEHOUSE_VERSION=0.3.0 python3 packaging/build.py` 显式构建发布版本；`0.3.0-rc.1` 会映射为 Debian 包版本 `0.3.0~rc.1`，二进制和 bundle 保持原始版本。版本支持三段数字与预发布后缀，不接受 `+build` 元数据。

`SOURCE_DATE_EPOCH` 默认取提交时间，源码包保留这个时间基准，传递给 dpkg-deb 控制包的时间基准；当前不保证 tar/gzip 归档逐字节可复现。源码归档限制目录和扩展名；Git 工作树仅打包索引中跟踪的文件，排除构建目录。非 Git 源码目录也不应混放实例数据。依赖锁定见 go.mod/go.sum 与 package-lock.json，许可证见 THIRD-PARTY-LICENSES.txt。

## 包和进程冒烟

构建完成后，本机 root 冒烟可在隔离的 Linux 开发/CI 环境执行：

~~~bash
sudo python3 tests/cli_smoke.py
sudo python3 tests/snapshot_smoke.py
python3 tests/tls_smoke.py
sudo python3 tests/process_smoke.py
~~~

CLI 测试调用打包的 amd64 CLI；TLS 测试调用打包的 HTTPS 入口。三进程测试使用 `build/process`，要求 AF_UNIX、回环 TCP、root 和 OpenSSH；它使用测试账号，不代替真实部署的跨 UID/systemd 检查。

arm64 测试：

~~~bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o build/gh-arm64.test ./internal/gh
qemu-aarch64-static build/gh-arm64.test -test.v
~~~

可选旧版迁移测试：

~~~bash
sudo env GHB_LEGACY_CLI_DEB=/absolute/path/gatehouse-cli_0.2.0_amd64.deb \
  python3 tests/upgrade_smoke.py
~~~

旧包由维护者从可信来源提供，不从任意 URL 自动下载。Go 测试另覆盖 schema 1 的记录与密文保留、活动核心锁定、损坏凭据和未知 schema 拒绝。

## CI 与发布

常规 CI 在 main 分支推送、PR 和手动执行时运行源码检查、Go/DOM 测试、双架构构建、包检查和可运行的进程冒烟，并上传构建产物（保留 14 天）。推送和 PR 若仅修改 Markdown、文档目录、文档构建配置或 Issue/PR 模板，则跳过代码 CI；手动执行始终运行全部检查。一次推送触发一次工作流，不逐个构建其中的 commit。文档仍由独立的 Documentation 工作流检查和部署。工作流采用固定上游 action commit 和最小只读权限，不能把“配置了工作流”当作已通过的远程结果。

版本发布前应审阅 CHANGELOG、检查构建身份与安装包版本一致，完成所需 Debian 目标机验收，再将经过验证的安装包作为 Release 资产上传。不要上传实例数据库、升级快照或含私人部署信息的旧 bundle。开发构建产物不等同于稳定 Release。

### 手动发布 Release

1. 审阅准备发布的变更和 CHANGELOG，无需修改任何源码版本常量。
2. 将变更合并到 main，进入 GitHub **Actions → Release → Run workflow**，分支选择 **main**。
3. 填写本次版本标签，例如 `v0.3.0`；预发布填写 `v0.3.0-rc.1` 并勾选预发布。标签后缀与开关必须一致。
4. 工作流检查版本和标签，然后复用完整 CI。全部成功后验证 SHA-256、二进制自报版本/提交与包版本，创建指向本次执行提交的标签和 Release，并上传所有 Debian 包、双架构 bundle、源码归档与校验清单。

Release 仅接受人工手动触发，不因 push、PR 或 tag 自动发布；只能从 main 执行。已有标签会被拒绝，不覆盖已发布版本。发布运行使用只读权限构建，仅发布任务具有仓库内容写权限。该流程发布下载附件，不升级任何已部署服务器。CI 附件解压后按版本目录组织，例如 `{{ docs_version }}/`。
