# 安装与首次部署

## 前提

- Debian 类 Linux，运行 systemd；提供 `amd64` 和 `arm64` 包。发行版兼容性以实际验收为准。
- 保留可以操作宿主机的 root/sudo 维护 SSH 会话。
- 准备管理员的 SSH **公钥**。私钥保留在客户端。
- 准备匹配公开 Web 主机名的 TLS 证书链和私钥。支持自有 CA，浏览器和客户端需信任该 CA。
- 初次安装与升级都会调用 apt 解析依赖，需可访问相应的软件源。

示例使用 `jump.example.com`。将其 DNS A/AAAA 记录指向实际入口地址；只添加可达的 IPv6 地址。SSH 域名应直接解析到入口，除非前面部署了真正支持原生 SSH 的代理。

## 网络

默认 Gatehouse SSH 为 TCP 2222，Web HTTPS 为 TCP 8443。根据部署需求配置云安全组和宿主机防火墙。Gatehouse 不自动修改防火墙、DNS、系统 sshd 或 22 端口。

~~~bash
dpkg --print-architecture
ps -p 1 -o comm=
sudo ss -lntp
~~~

NAT 部署时，`public_host` 和 `public_port` 填写客户端可达的映射地址；`ssh_listen` 是服务器本机监听地址。`web_url` 必须是实际访问的 HTTPS origin，包含非默认端口，不能带路径或查询参数。

## 安装包

从 [Releases](https://github.com/zwz211123/gatehouse/releases) 获取对应架构的完整 bundle，解压到独立目录。

{{ download_notice }}

~~~bash
mkdir gatehouse-install
GATEHOUSE_VERSION='{{ download_version }}'
tar -xzf "gatehouse-${GATEHOUSE_VERSION}-amd64.tar.gz" -C gatehouse-install
cd gatehouse-install
sha256sum -c SHA256SUMS-amd64
sudo bash install.sh
~~~

每个架构 bundle 包含 core、ssh、web、cli 四个组件及 `gatehouse` 元包。组件必须安装相同版本，不要混装架构。包内摘要用于发现文件损坏，不代替对下载来源的信任。

## 首次初始化

预先将管理员公钥放到 `/root/admin.pub`，将证书链和匹配私钥放到 `/root/tls/`。使用自己的文件路径：

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
~~~

`init` 只用于空实例，生成数据库、凭据库主密钥和产品 SSH 主机身份，并登记首位所有者。它会将 TLS 对复制到 `/etc/gatehouse/tls/` 的独立目录，配置所需服务用户读取权限。输入文件不被修改。已有实例不要重复初始化。

## 启动与验收

~~~bash
sudo bash acceptance.sh
ghbctl version
sudo ghbctl status
~~~

`acceptance.sh` 执行 doctor、启用并启动服务、检查管理 socket 与跨 UID 隔离。只通过本机检查还不够，应完成一次业务流程：

1. 普通管理员公钥 SSH 登录。
2. `web login` 获取 token，登录 HTTPS 管理器。
3. 添加一个真实目标的已核验主机公钥、凭据与目标账号，测试连接。
4. 在菜单连接目标，退出后返回菜单。
5. 申请临时入口，在新终端执行返回命令，撤销后确认连接关闭。

## 文件与服务

| 位置 | 用途 |
| --- | --- |
| `/etc/gatehouse/config.json` | 入口、监听、数据路径与 TLS 路径 |
| `/var/lib/gatehouse/` | SQLite、主密钥及产品 SSH 主机密钥 |
| `/run/gatehouse/` | 内部 Unix socket 与本机管理入口 |
| `/usr/lib/gatehouse/ghb-{core,ssh,web}` | 三个服务程序 |
| `/usr/bin/ghbctl` | root 本机管理工具 |

服务为 `gatehouse-core`、`gatehouse-ssh`、`gatehouse-web`。systemd unit 使用默认数据和运行目录；若自定义 `--data` 或 `--run`，须同步调整 RuntimeDirectory、ReadWritePaths 和目录所有权。

## TLS 与监听变更

证书轮换：

~~~bash
sudo ghbctl tls --tls-cert /root/tls/new-fullchain.pem --tls-key /root/tls/new-key.pem
sudo systemctl restart gatehouse-web
~~~

命令检查有效期、主机名与密钥匹配，使用新的证书目录并原子更新配置。它不向浏览器安装根 CA。修改监听地址等配置后，执行 doctor 并重启相应服务。

~~~bash
sudo ghbctl doctor
sudo journalctl -u gatehouse-core -u gatehouse-ssh -u gatehouse-web --since '-10 min'
~~~

卸载 `remove` 保留数据；`purge gatehouse-core` 会删除默认 `/etc/gatehouse` 与 `/var/lib/gatehouse`。卸载前先准备经过验证的独立备份。
