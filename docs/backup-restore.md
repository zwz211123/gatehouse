# 备份、恢复与应急管理

## 日常备份

`ghbctl` 的本机管理要求 root。准备独立的备份口令文件，至少 16 个字符，建议随机生成并设置 0600。不要将口令写进命令行历史。

~~~bash
sudo ghbctl backup --file /root/gatehouse-backup.ghb --passphrase-file /root/backup-passphrase
sudo ghbctl export-master --file /root/gatehouse-master.key
~~~

`.ghb` 使用 scrypt 与 AES-GCM 加密，包括一致性数据库快照和产品 SSH 主机身份，**不包含凭据库 master.key**。独立主密钥应与归档分开放在受保护位置。没有匹配的主密钥无法恢复已保存的目标私钥。

备份排除临时账号秘密；token、Web 会话和活动连接不恢复。当前机器的配置和 TLS 路径保留，归档内的配置用于人工核对。仅有数据库文件不能替代完整恢复材料。

## 恢复

~~~bash
sudo systemctl stop gatehouse-web gatehouse-ssh gatehouse-core
sudo ghbctl restore --file /root/gatehouse-backup.ghb --passphrase-file /root/backup-passphrase
sudo systemctl start gatehouse-core gatehouse-ssh gatehouse-web
~~~

迁移到新机器时，应先按默认部署准备服务用户、配置、证书及权限，将匹配主密钥放到数据目录的 `master.key` 并设为 0600、归属于核心数据所有者。新机器的 Web origin 和入口地址按实际情况配置。

恢复检查归档、数据库完整性、主机密钥对、有效所有者及凭据解密，通过切换数据目录保留恢复前目录。核心与离线管理共享独占锁，不能并发恢复。

Web 的 `backup.create` 允许下载加密备份；`backup.restore` 只验证并暂存最大 16 MiB 的归档。正式切换仍需本机停服，较大备份使用 CLI。

## 接入公钥全部丢失

宿主机 root 可以停服后恢复一个所有者公钥：

~~~bash
sudo systemctl stop gatehouse-web gatehouse-ssh gatehouse-core
sudo ghbctl recover-owner --user admin --public-key /root/new-admin.pub
sudo systemctl start gatehouse-core gatehouse-ssh gatehouse-web
~~~

命令会写审计、启用该所有者及其公钥，解除针对该用户的直接拒绝并移出含拒绝授权的组。它不是 Web 远程找回入口。不要用 `init` 代替所有者恢复。

## 运维变更

在线记录查看与更改可用 `ghbctl list --kind KIND`、`ghbctl apply --file change.json`。变更结构与 Web API 相同，更新/删除需 id 和当前 ETag。主机 TLS/监听配置由本机管理员管理，业务配额由 Web 安全设置管理。

升级专用 root 快照包含原始主密钥、TLS 和旧程序，其用途与日常 `.ghb` 加密备份不同，见 [UPGRADE.md](../UPGRADE.md)。应定期在隔离环境演练恢复，不能只检查归档文件存在。
