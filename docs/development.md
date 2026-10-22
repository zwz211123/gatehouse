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

## Debian 包

~~~bash
GATEHOUSE_GO=go python3 packaging/build.py
GHB_QEMU=/usr/bin/qemu-aarch64-static python3 tests/packages.py
~~~

产物位于 `dist/0.2.1/`：8 个架构组件 deb、1 个元包、每架构 bundle、源码归档及 SHA-256 清单。amd64 使用通用 `GOAMD64=v1`，两个架构均 `CGO_ENABLED=0`。构建不安装包，不修改宿主机服务。

`SOURCE_DATE_EPOCH` 传递给 dpkg-deb 控制包的时间基准；当前不保证 tar/gzip 归档逐字节可复现。源码归档限制目录和扩展名；Git 工作树仅打包索引中跟踪的文件，排除构建目录。非 Git 源码目录也不应混放实例数据。依赖锁定见 go.mod/go.sum 与 package-lock.json，许可证见 THIRD-PARTY-LICENSES.txt。

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

常规 CI 在提交和 PR 上执行源码检查、Go/DOM 测试、双架构构建、包检查和可运行的进程冒烟，并上传构建产物。工作流采用固定上游 action commit 和最小只读权限，不能把“配置了工作流”当作已通过的远程结果。

版本发布前应审阅 CHANGELOG、确认源码版本与安装脚本/包版本一致，完成所需 Debian 目标机验收，再将经过验证的安装包作为 Release 资产上传。不要上传实例数据库、升级快照或含私人部署信息的旧 bundle。开发构建产物不等同于稳定 Release。
