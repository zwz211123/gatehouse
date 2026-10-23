# 使用指南

## 身份与连接

Gatehouse 用户与 Linux 账号不同。普通用户用接入公钥登录受控菜单；临时用户名以 `ghp_` 开头，不写入 `/etc/passwd`，不用 PAM，也不获得宿主机 shell。

~~~bash
ssh -p 2222 -i ~/.ssh/id_ed25519 admin@jump.example.com
~~~

产品 SSH 主机身份与系统 sshd 不同。首次连接应通过服务器的 `/var/lib/gatehouse/host.pub` 或管理员提供的可信渠道核验，而不是盲目接受未知指纹。

菜单命令：

~~~text
list
info ACCOUNT_ID
connect ACCOUNT_ID
connect ACCOUNT_ID 1800
connect 服务器名
connect 服务器名 1800
proxy create
proxy list
proxy show TICKET_ID
proxy delete TICKET_ID
proxy revoke TICKET_ID
web login
web revoke
web confirm DIGEST
whoami
clear
help
exit
~~~

`list` 显示获授权的目标账号。`connect` 进入目标终端，退出后回到菜单；可显式指定最长连接时限（秒）。也可使用 `connect 服务器名 [秒数]`，服务器名精确匹配 Web 管理中填写的服务器名称（支持中文和空格）。只有一个已启用且具有当前来源直连权限的可用账号时直接连接；多个时显示服务器地址、用户名和账号 ID，输入序号选择，`0` 或空行返回。无可用账号时显示提示。重名服务器的账号会一起列出；账号 ID 优先于服务器名，完整名称优先于末尾秒数解析。最终连接仍校验时长、来源和授权。菜单本身不提供任意本机命令或转发。

在交互终端按 Tab 可补全命令、子命令、获授权的账号 ID、可用服务器名和自己的临时凭据 ID。候选带用途说明，支持模糊匹配（例如 `clr` → `clear`），再次按 Tab 循环选择。JSON 和数字选择提示中不启用命令补全。`clear` 清除当前屏幕与终端支持的滚动历史；Ctrl+L 重绘当前屏幕。

`proxy create` 先显示连接信息，再提供数字菜单：`0` 跳过或返回，其他序号查看对应用途的快捷命令，也可选择“显示全部”。查看后可继续选择其他用途。

`proxy list` 显示自己的凭据序号，输入序号可重看连接信息和快捷命令；输入 `d1` 可直接删除序号 1 的凭据，`d all` 批量清理自己的全部可删除凭据。单条和批量采用相同规则：没有活动连接，且已撤销、已过期或连接次数已经全部耗尽，才能删除。仍有剩余次数且未撤销、未过期的凭据会保留，即使之前已经使用过。也可使用 `proxy show TICKET_ID` 和 `proxy delete TICKET_ID`。删除会一并清理密码与失败计数，保留审计日志；活动连接尚未关闭时需稍后重试。

新申请的临时密码按明文保存在受保护的本机数据库中，仅申请人可经普通 SSH 菜单重看；其他用户的 `proxy.read` 仍只允许读取元数据。旧版本只保存密码哈希，升级后仍可认证，但无法恢复密码，需重新申请。导出的备份继续排除所有临时凭据。

## Web 登录与更改确认

在普通 SSH 菜单执行 `web login`，使用输出的 HTTPS 地址与 token 登录。token 有效 120 秒，只能兑换一次。Web 会话空闲上限 15 分钟、绝对上限 2 小时，依赖原菜单连接继续在线。

创建或修改记录时，Web 会显示 `web confirm DIGEST`。在原 SSH 菜单执行它，将返回的确认码填回页面。确认绑定本次请求的原始正文；修改任何字段都需要重新确认。确认码不是登录 token。

## 接入目标

1. 凭据库选择导入已有私钥或生成新 Ed25519 密钥。已有记录默认保留密钥；生成和导入不能同时选择。
2. 将凭据的公钥安装到目标账号的 `authorized_keys`。Gatehouse 不自动改写后端文件。
3. 添加目标地址、SSH 端口和通过可信渠道核验的服务器主机公钥，可保存多种算法。
4. 新建目标账号，按名称选择服务器与凭据，填写远端用户名，例如 `deploy`。
5. 测试连接，再为用户或用户组分配具体能力和资源范围。

目标私钥的查询接口不返回私钥或密文。主机公钥是核验远端身份的材料，接入用户公钥是核验用户身份的材料，两者不能互换。

## TTL 和连接时长

`ttl` 是临时账号可领取或重连的窗口，`duration` 是每次已认证连接的最长时长，均以整数秒计。省略或填写 0 时仍使用默认值：TTL 300 秒、连接时长 7200 秒；最小值分别为 15 秒和 10 秒。自 0.3.2 起取消 600 秒 / 86400 秒硬上限及全局时间配额，只保留适用授权及父授权的限制。所有者可直接申请更大数值，例如 `"ttl":604800,"duration":315360000`（7 天领取、每次最多 10 年）。`connect ACCOUNT_ID SECONDS` 同样支持大时长。

amd64/arm64 API 和 SSH 菜单接受有符号 64 位整数；TTL 加上当前 Unix 秒数必须仍可表示。超大时长按秒比较，不会转换为纳秒后溢出。Web 数值表单使用 JavaScript 安全整数范围（最大 9007199254740991），更大的精确整数请通过 SSH JSON 提交。授权失效、撤销、次数耗尽和核心重启撤销临时账号等规则仍然生效；这里只取消固定时间上限。

## 临时交互终端

在菜单执行 `proxy create` 后提交一行 JSON，替换实际 `ACCOUNT_ID`：

~~~json
{"account":"ACCOUNT_ID","modes":["shell"],"pty":"require","ttl":300,"duration":1800,"total":1,"concurrent":1,"sessions":1,"channels":1}
~~~

输出包含临时用户名、随机密码、堡垒机入口、目标账号、有效期、用途、主机指纹和撤销命令，完整复制命令通过数字菜单按需查看。新终端凭这组临时账号密码认证，直接进入已指定的目标终端。

复制命令需要 Bash、OpenSSH 和 sshpass；Debian 客户端可安装 `openssh-client sshpass`。其他工具可填写同一组连接信息，但实际协议请求仍必须符合申请。默认连接次数耗尽或断线不会自动返还；多连接和重连需显式申请并授权。

同时需要 shell 与 SFTP 的工具可以申请：

~~~json
{"account":"ACCOUNT_ID","modes":["shell","sftp"],"pty":"allow","file_root":"/srv/work","file_ops":["read","write","list"],"ttl":300,"duration":1800,"total":3,"concurrent":2,"sessions":2,"channels":4,"reconnect":true}
~~~

每个申请用途都会生成独立的复制命令，使用同一临时连接信息；数字菜单可逐个查看或显示全部。每条命令都会单独建立连接，并共享账号的连接次数、并发、重连与有效期限制，显示全部不会自动增加配额。工具自动请求的额外命令、环境、通道或转发不会因为工具名称而被放行。

## 固定命令

~~~json
{"account":"ACCOUNT_ID","modes":["exec"],"command":"uname -a","pty":"forbid","ttl":120,"duration":60}
~~~

服务器检查实际 exec 字符串精确一致。非所有者还需对应命令摘要用途资源，见[权限指南](permissions.md)。命令字符串固定不意味着脚本内容或程序行为永不变化。

## SFTP 与现代 SCP

~~~json
{"account":"ACCOUNT_ID","modes":["sftp"],"pty":"forbid","file_root":"/srv/files","file_ops":["read","list"],"duration":1800}
~~~

~~~json
{"account":"ACCOUNT_ID","modes":["scp"],"pty":"forbid","file_root":"/srv/files","file_ops":["read","write","list","metadata"],"local_path":"/home/me/upload.bin","remote_path":"/srv/files/upload.bin","direction":"upload","duration":1800}
~~~

SCP 使用现代 SFTP 协议，不支持 `scp -O`。文件操作分别为 `read`、`write`、`list`、`mkdir`、`remove`、`rename`、`metadata`。远端路径必须符合 `file_root`。某些 SCP 操作需要属性修改权限，应按实际需求授权。

普通路径检查不对抗远端并发符号链接替换。`strict_path=true` 仅在目标账号已验证 chroot、账号记录的 `chroot_verified=true` 且 `file_root=/` 时开放；此 `/` 是远端受限账号看到的隔离根。

## 固定 TCP 转发

~~~json
{"account":"ACCOUNT_ID","modes":["tcp"],"tcp_host":"127.0.0.1","tcp_port":3306,"local_port":13306,"pty":"forbid","duration":1800,"channels":16}
~~~

默认通过目标 SSH 连接目标侧的固定数字 IP 和端口，生成回环本地 `-L` 命令。`tcp_route=jump` 改为由堡垒机直拨，另需独立授权。服务器校验真实目的端点，看不到客户端本地监听地址，也不能可靠区分客户端的 `-L` 与 `-D` 界面意图。

从 0.3.1 起，`channels` 限制每条 SSH 连接当前打开的通道数，包含 session 和 TCP 转发通道；关闭后释放名额，不累计历史打开次数。转发 Web 时，一个浏览器可能同时建立多条 TCP 连接，应为实际并发量设置足够的 `channels`。`total` 仍是临时账号可认证的 SSH 连接总次数，`concurrent` 是同时在线的 SSH 连接数；`sessions` 仍单独限制每条 SSH 连接可创建的 session 数。超过并发通道限制仍会拒绝请求并使该临时凭据失效。

不支持反向 `-R`、任意透明 ProxyJump、agent/X11 或 Unix socket 转发。完整目标 shell 的正常文件读写由远端账号权限决定。
