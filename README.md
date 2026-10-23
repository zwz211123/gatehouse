# Gatehouse

[文档网站](https://zwz211123.github.io/gatehouse/) · [English](README.en.md) · [快速上手](docs/quickstart.md) · [安装](docs/installation.md) · [使用](docs/usage.md) · [权限](docs/permissions.md) · [升级](UPGRADE.md)

面向 Debian 与衍生系统的 SSH 堡垒机。用户通过公钥进入受控菜单，再连接获授权的目标服务器；也可以申请用途固定的临时账号，让标准 SSH 客户端和第三方工具直接连接指定目标。

Web 管理器没有账号密码、TOTP 或 Passkey 登录。只有已登录普通 SSH 菜单的用户，才能执行 `web login` 获取一次性 token。临时账号不能签发 Web token。

## 主要能力

- 管理目标服务器、SSH 主机公钥、登录私钥、目标账号、用户、公钥和用户组。
- 按操作、资源、来源网段、时间、连接数、通道数、流量及速率授权；支持有父子关系的权限委派和级联撤销。
- 临时交互终端、固定远端命令、SFTP、现代 SCP 和固定目的 TCP 转发。
- 每次申请输出临时用户名、密码、完整连接信息与已填写参数的 Bash 命令。新连接使用临时密码，不需要原用户私钥。
- Web 保存操作绑定 SSH 单次确认码，并检查记录版本，防止旧页面覆盖新配置。
- SQLite 凭据库、加密备份、独立主密钥导出、离线恢复及本机所有者恢复。
- 四个组件包及元包；支持 `amd64`、`arm64`。安装后不需要 Go 或 Node.js。

管理器当前为中文界面。项目以单节点、单核心部署为目标；兼容第三方客户端不代表不受限制的透明 SSH 中继。

## 安装

需要运行 systemd 的 Debian 类 Linux、管理员接入公钥，以及匹配 Web 域名的 TLS 证书与私钥。默认产品端口为 SSH `2222`、HTTPS `8443`，保留系统原有 SSH。

从本仓库的 [Releases](https://github.com/zwz211123/gatehouse/releases) 下载对应架构的安装包；若尚无发布资产，可按[构建文档](docs/development.md)自行生成。

~~~bash
mkdir gatehouse-install
tar -xzf gatehouse-0.2.1-amd64.tar.gz -C gatehouse-install
cd gatehouse-install
sha256sum -c SHA256SUMS-amd64
sudo bash install.sh
~~~

首次安装后，使用自己的地址、TLS 文件和公钥初始化：

~~~bash
sudo ghbctl init \
  --user admin \
  --public-key /root/admin.pub \
  --public-host jump.example.com \
  --public-port 2222 \
  --web-url https://jump.example.com:8443 \
  --web-listen 0.0.0.0:8443 \
  --tls-cert /root/tls/fullchain.pem \
  --tls-key /root/tls/key.pem

sudo bash acceptance.sh
~~~

`example.com` 是占位域名。部署前应完成 DNS、防火墙、证书信任及文件准备；完整步骤见[安装文档](docs/installation.md)。已有实例升级时不要再次运行 `init`，使用 [UPGRADE.md](UPGRADE.md) 中的升级流程。

## 使用

~~~bash
ssh -p 2222 -i ~/.ssh/id_ed25519 admin@jump.example.com
~~~

登录后为 Gatehouse 菜单，不是宿主机 shell：

~~~text
list
connect ACCOUNT_ID
web login
proxy create
~~~

在 Web 中依次准备凭据、登记服务器、绑定目标账号、分配权限。后端无需安装 Gatehouse agent，通常只需现有 SSH 服务和正确的 `authorized_keys`。详见[用户指南](docs/usage.md)。

## 安全边界

临时凭据是持有即可使用的短期凭据。权限约束作用于服务端可见的 SSH 请求；完整目标 shell 内的程序和文件权限仍由目标账号控制。SFTP 只读授权不会限制用户同时拥有的 shell。

宿主机 root、核心服务和部署配置属于可信边界。审计是本地事件记录，不提供终端录像、外部不可篡改日志或高可用。严格文件路径隔离需要目标侧已核验的 chroot；普通路径检查不等同于系统级沙箱。

更多边界见 [SECURITY.md](SECURITY.md) 与[架构文档](DESIGN.md)。

## 构建与贡献

~~~bash
go mod download
go test -race ./...
go vet ./...
python3 packaging/build.py
~~~

Go 最低版本见 `go.mod`。前端作为 HTML/CSS/JavaScript 静态嵌入，无运行时 CDN 或前端构建服务。开发与测试依赖见 [CONTRIBUTING.md](CONTRIBUTING.md)、[docs/development.md](docs/development.md)。

[测试状态](TEST-REPORT.md) 区分本地测试、模拟架构测试与真实系统验收。打包成功不代表已通过所有发行版、客户端或生产环境验证。

## 许可证

[MIT](LICENSE)。第三方许可证见 [THIRD-PARTY-LICENSES.txt](THIRD-PARTY-LICENSES.txt)。
