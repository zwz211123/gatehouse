# 快速上手

目标：从空实例开始，完成“登录菜单 → 登记目标 → 连接目标 → 签发临时入口”。已有实例应走[升级流程](../UPGRADE.md)，不要重新初始化。

## 1. 部署入口

按[安装与首次部署](installation.md)准备 Debian 类 systemd 主机、管理员公钥、Web TLS 证书和安装包。示例地址 `jump.example.com` 必须替换为自己的地址。

默认 SSH 为 `2222`，HTTPS 为 `8443`。先完成 DNS 与端口放行，保留系统原有维护 SSH，再执行安装、`ghbctl init` 和 `acceptance.sh`。

## 2. 用公钥登录菜单

~~~bash
ssh -p 2222 -i ~/.ssh/id_ed25519 admin@jump.example.com
~~~

首次接入前，从可信渠道核验产品 SSH 主机公钥，例如服务器 `/var/lib/gatehouse/host.pub`。成功后看到 Gatehouse 菜单，可以执行 `help`；这里不是宿主机 shell。

也可在本地 `~/.ssh/config` 添加：

~~~sshconfig
Host gatehouse
    HostName jump.example.com
    Port 2222
    User admin
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    ServerAliveInterval 30
    ServerAliveCountMax 3
~~~

之后执行 `ssh gatehouse`。别名保存在客户端文件中，与服务器上的目标账号名称无关。

## 3. 打开 Web 管理器

在菜单中执行：

~~~text
web login
~~~

打开输出的 HTTPS 地址并兑换 token，保持这个 SSH 菜单在线。添加或修改记录时，按页面提示回到原菜单执行 `web confirm DIGEST`，将确认码填回页面。

## 4. 登记一个目标

1. 在凭据库导入已有目标私钥，或生成新的 Ed25519 密钥。
2. 确认对应公钥已安装到后端远端用户的 `authorized_keys`。
3. 添加服务器的地址、SSH 端口，以及通过可信渠道核验的主机公钥。
4. 创建目标账号，选择服务器和凭据，填写后端用户名，例如 `deploy`。
5. 测试连接。普通用户还需[授予目标访问权限](permissions.md)，所有者可用于首次验证。

导入已有凭据时选择“导入”；生成新密钥后必须把新公钥安装到后端。仅登记后端主机公钥不能让它接受登录。

## 5. 先通过菜单连接

~~~text
list
info ACCOUNT_ID
connect ACCOUNT_ID
~~~

将 `ACCOUNT_ID` 换成 `list` 中的实际 ID。在目标 shell 中执行 `exit` 后返回菜单。若失败，先按[故障排查](troubleshooting.md)区分主机身份、目标凭据和授权问题。

## 6. 给新终端签发临时入口

在菜单执行 `proxy create`，然后提交一行 JSON：

~~~json
{"account":"ACCOUNT_ID","modes":["shell"],"pty":"require","ttl":300,"duration":1800,"total":1,"concurrent":1,"sessions":1,"channels":1}
~~~

把输出的完整命令粘贴到新终端执行，或将临时用户名、密码和堡垒机入口填入支持对应请求的客户端。生成的 Bash 命令需要 OpenSSH 和 `sshpass`。

这次申请只允许一次 shell 连接，新连接需在 300 秒内认证，连接最长持续 1800 秒。固定命令、文件传输和 TCP 转发另见[使用指南](usage.md)，不要把 shell 申请直接当作 SFTP 凭据。

完成后可用 `proxy list` 查看申请，执行输出的 `proxy revoke TICKET_ID` 撤销，并验证临时连接被关闭。首次部署的完整验收清单见[安装文档](installation.md)。
