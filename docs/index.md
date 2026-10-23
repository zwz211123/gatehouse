# Gatehouse

<div class="hero" markdown>

让标准 SSH 客户端接入受控堡垒机。

通过公钥登录、按需授权，再签发绑定目标与用途的短期连接信息。继续使用熟悉的终端和文件工具，让访问控制留在服务端。

[快速上手](quickstart.md){ .md-button .md-button--primary }
[查看源码](https://github.com/zwz211123/gatehouse){ .md-button }

</div>

Gatehouse 面向运行 systemd 的 Debian 类 Linux，提供 `amd64`、`arm64` 安装包。当前文档对应 **0.2.1**，Web 管理器为中文界面。

## 从这里开始

| 你要做的事 | 阅读入口 |
| --- | --- |
| 了解普通身份、目标凭据和临时账号 | [核心概念](concepts.md) |
| 第一次部署并连通一个目标 | [快速上手](quickstart.md)、[完整安装](installation.md) |
| 登录菜单、Web 或申请临时连接 | [使用指南](usage.md) |
| 使用 SSH、SFTP、SCP 和本地 TCP 转发 | [客户端兼容](clients.md) |
| 为其他用户授权或委派 | [权限与委派](permissions.md) |
| 升级、备份与处理故障 | [升级](../UPGRADE.md)、[备份恢复](backup-restore.md)、[故障排查](troubleshooting.md) |

## 接入流程

普通用户用公钥进入 Gatehouse 菜单，可以直接连接获授权的目标，也可以申请一组临时用户名和随机密码。新终端或第三方工具使用这组连接信息访问堡垒机，由服务端校验目标、协议用途和配额后连接后端。

Web 登录同样从普通 SSH 菜单发起：执行 `web login` 换取一次性 token。没有独立的 Web 账号密码入口；Web 更改还需原 SSH 会话确认。

## 项目能力

- 管理服务器、目标账号、加密凭据、公钥、用户和用户组。
- 按能力、资源、来源网络、时间窗与连接/流量配额授权，支持权限委派和级联撤销。
- 为 shell、固定 exec、SFTP、现代 SCP 和固定目的 TCP 转发签发临时入口。
- 通过独立核心、SSH 和 HTTPS 入口运行，提供本机管理工具、加密备份与离线恢复。

## 使用范围

Gatehouse 当前以**单节点、单核心**部署为目标。支持标准协议不等于所有客户端功能都能放行；工具发送的请求必须符合申请，详细限制见[客户端兼容](clients.md)。

目标 shell 的权限由目标系统账号控制。本地事件审计不包含终端录像，也不提供外部不可篡改日志。部署前请阅读[安全边界](../SECURITY.md)与[测试状态](../TEST-REPORT.md)。

项目使用 [MIT 许可证](../LICENSE)。安装包以仓库 [Releases](https://github.com/zwz211123/gatehouse/releases) 的实际资产为准；没有所需资产时可按[构建文档](development.md)生成。
