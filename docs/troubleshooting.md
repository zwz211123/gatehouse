# 故障排查

## 先确认故障发生在哪一段

系统维护 SSH、Gatehouse 菜单 SSH、后端 SSH、HTTPS 是不同连接。保留具体错误、时间、服务版本和相关日志，公开 issue 前移除真实 token、临时密码、私钥、数据库及不必要的部署地址。

~~~bash
ghbctl version
sudo ghbctl doctor
sudo ghbctl status
systemctl status gatehouse-core gatehouse-ssh gatehouse-web
sudo journalctl -u gatehouse-core -u gatehouse-ssh -u gatehouse-web --since '-10 min'
~~~

## host key is unverified or changed

这是后端服务器主机身份不匹配，不是 Web TLS 错误。通过可信渠道核对目标 `/etc/ssh/ssh_host_*_key.pub`，将实际可能协商的主机公钥加入服务器记录。当前版本可能选择另一种算法；仅保存 Ed25519 而服务器同时提供 ECDSA/RSA 时，应核验并保存所需算法的对应公钥。主机重装或密钥轮换后需重新核验。

不要禁用验证或直接信任未经核验的扫描结果。

## unable to authenticate / attempted methods none publickey

目标账号或私钥不匹配。确认目标用户名、绑定凭据、公钥是否已加入目标的 authorized_keys，以及目标 SSH 权限/策略。导入已有私钥时明确选择“导入”，已有记录编辑默认“保留”。如果选择生成新密钥，目标侧必须部署新公钥。

接入菜单用的用户公钥与连接目标用的凭据是两套独立身份。

## Web token 失效或 401

普通菜单 SSH 应保持在线；token 120 秒单次兑换。原会话退出、撤销、服务重启或 Web 会话到期后重新获取 token。临时代理账号不能申请 Web 登录。

## Web 403 或旧确认失败

检查实际操作能力、资源、来源 CIDR、时间窗和父授权，不要仅看能否打开页面。更改正文后必须重新在原 SSH 菜单确认。ETag 冲突时刷新并重新编辑，不能复制旧 ETag 强行覆盖。

## HTTPS 证书错误

核对 Web origin、证书 SAN、有效期、链和私钥。自建 CA 需要客户端主动信任根 CA；服务端安装证书不等于客户端已经信任它。使用 `ghbctl tls` 轮换已初始化实例的证书对。

## 工具连接后立即关闭

核对工具发送的请求与申请的模式、PTY、固定命令、环境、路径、目的端点和通道数。需要多次连接或重连时显式申请并授权。现代 SCP 走 SFTP，不支持 legacy `scp -O`。

## 升级或 doctor 失败

不要运行 init。查看脚本输出的失败项和升级快照目录；未知 schema、损坏凭据或身份不一致都应停止。按 [UPGRADE.md](../UPGRADE.md) 评估恢复，不能对运行中的数据覆盖快照。
