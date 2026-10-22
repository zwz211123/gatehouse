# 权限与委派

普通用户默认没有目标访问能力。所有者是初始全局信任主体；任命新所有者属于独立高权限操作，不是普通委派的升级途径。

## 授权记录

每条授权指定用户 `subject` 或用户组 `group`，二者选一；并同时约束：

- `actions`：允许或拒绝的能力。
- `resources`：资源 ID 或精确用途资源，`*` 为全局范围。
- `not_before` / `expires`：生效与失效时间，0 表示不增加对应边界。
- `cidrs`：实际网络来源范围，空数组表示不额外限制。
- `limits`：时限、次数、连接和通道数、流量及速率。
- `parent` / `depth`：来源授权和剩余下放层数。
- `enabled` / `deny`：是否启用，以及是否为拒绝规则。

Web 表单按名称选择对象，存储的关联值仍是稳定 ID。不能读取的已有引用会作为不可见选项保留，不会因页面缺少读取权限而被隐式清空。

## 常见能力

| 范围 | 能力 |
| --- | --- |
| 菜单连接 | `shell.direct` |
| 临时入口 | `proxy.create/read/revoke`，以及 `proxy.shell/exec/sftp/scp/tcp` |
| 多连接与重连 | `proxy.multi`、`proxy.reconnect` |
| 特殊 TCP 路由 | `proxy.tcp.jump`、`proxy.tcp.special` |
| 管理对象 | `asset/account/credential/user/key/group/grant` 的相应增删改查能力 |
| 凭据操作 | `credential.import/generate/bind/test` |
| 额外管理信任 | `user.owner`、`asset.trust/special`、`account.chroot` |
| Web | `web.login` |
| 运维 | `session.read/terminate`、`audit.read/export`、`config.read/update`、`backup.create/restore` |

上表为便于阅读的缩写，协议中的能力字符串不含斜杠。完整名称以 [`Capabilities`](../internal/gh/model.go) 为准；未知能力不会自动获得语义。

查看一个对象和修改它是不同权限；绑定凭据还检查凭据绑定及对应资产权限。Web 隐藏或显示控件不是最终授权依据，核心服务对每次请求重新检查。

## 最小目标连接示例

为用户授予一个目标账号上的普通连接和临时终端：

~~~json
{
  "subject":"USER_ID",
  "group":"",
  "actions":["account.read","shell.direct","proxy.create","proxy.shell","proxy.read","proxy.revoke"],
  "resources":["ACCOUNT_ID"],
  "parent":"",
  "not_before":0,
  "expires":0,
  "depth":0,
  "enabled":true,
  "deny":false,
  "limits":{"max_duration":7200,"max_ttl":300,"max_total":1,"max_concurrent":1,"max_sessions":1,"max_channels":1,"max_bytes":0,"max_rate":0},
  "cidrs":[]
}
~~~

若需要 Web，再单独授予 `web.login` 于资源 `*`，并按需要授予对象读取/管理能力。仅登录 Web 不赋予服务器访问权限。

## 精确用途资源

非所有者使用部分能力时，除账号上的基础能力外，还需匹配用途资源：

| 用途 | 精确资源 |
| --- | --- |
| exec | `ACCOUNT_ID:exec:SHA256(command)` |
| 文件目录 | `ACCOUNT_ID:file:/srv/files` |
| 经目标 SSH 的 TCP | `ACCOUNT_ID:tcp:IP:PORT` |
| 跳板机直拨 TCP | `ACCOUNT_ID:tcp:jump:IP:PORT` |

exec 摘要为原始 UTF-8 命令的 SHA-256 小写十六进制；不进行空白规范化。文件用途不是模糊目录前缀通配，较小目录应签发对应精确资源。TCP 使用申请中固定的数字地址、路由和端口。

## 委派和拒绝

父授权包含 `grant.create` 及需要的管理能力，并设置正数 `depth`，接收者才能以该授权为 parent 继续下放。子授权的能力、资源、时间、CIDR、配额不得超出父授权，depth 必须更小。

普通委派管理员只能修改或删除自己签发的普通授权，不能删除所有者拒绝规则，或通过删除拒绝组、移除成员、删除所有者来绕过约束。组成员变更同样经过委派检查。

来源匹配的拒绝规则优先。父授权收回、失效或委派人受到新的拒绝约束后，下级权限重新计算；相关活动连接会在实时检查或维护周期中关闭。维护周期通常约 1 秒，并不意味着所有网络故障都能在 1 秒内发现。

## 配额

时间单位为秒，流量为字节，速率为字节/秒。`max_bytes` 是一个申请的全部连接和通道累计流量；`max_rate` 为共享速率。0 表示该条规则不额外限制，仍受其他授权和全局设置约束。多个权限记录不能被当成绕过上级限制的独立额度。
