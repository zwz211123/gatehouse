# 升级已有实例

适用于已有 schema 1 的 Gatehouse 0.2.0 实例升级到 0.2.1。**不要重复 init，不要删除数据目录。** 使用系统原有 root/sudo 维护 SSH；Gatehouse 自身连接会被重启断开。

## 执行升级

下载新版本对应架构 bundle，解压到新的目录，保留旧版安装包。以下示例使用 amd64：

~~~bash
mkdir gatehouse-0.2.1
tar -xzf gatehouse-0.2.1-amd64.tar.gz -C gatehouse-0.2.1
cd gatehouse-0.2.1
sha256sum -c SHA256SUMS-amd64
sudo bash install.sh
~~~

安装成功后单独执行：

~~~bash
sudo bash acceptance.sh
ghbctl version
sudo ghbctl status
systemctl is-active gatehouse-core gatehouse-ssh gatehouse-web
~~~

版本应显示 `0.2.1`。重新建立普通菜单 SSH，执行 `web login` 获取新 token。继续使用原域名、端口和 TLS，强制刷新网页后确认新版本。任何一步失败时保留输出并停止后续操作，不应重新初始化或强行跳过检查。

## 自动保护

安装脚本核验 deb 摘要，停止三个服务，再使用新 CLI 离线验证旧数据：数据库完整性、schema、JSON、凭据解密、公钥/指纹与 SSH 主机密钥对。运行中的核心和未知 schema 会被拒绝。

随后生成 `/var/backups/gatehouse/upgrade-0.2.1-XXXXXXXX/` 快照，包含数据目录和 WAL、配置目录、实际 TLS 对、旧程序及 unit。目录 0700，归档与清单 0600；**此恢复点含主密钥和私钥，只供 root 保管**，不是 Web 的加密 `.ghb` 备份。

安装五个同版本包后再次检查，并比较原始 JSON、修订号、审计、配置、主密钥、SSH 身份和 TLS 摘要。一致后运行 doctor 并启动服务；失败保持停止。直接 apt 安装 deb 不执行这层快照和前后比较，升级应使用 bundle 的 `install.sh`。

schema 仍为 1，兼容过程不重新加密或重写记录。服务重启会使内存中的 token 和 Web 会话失效；已有临时连接不承诺跨重启继续使用。脚本不修改 DNS、防火墙或系统 sshd。

## 回退

回退到快照会丢弃之后的 Gatehouse 配置和审计。先另存当前数据，再在维护 SSH 中操作。以下 `backup` 必须替换成安装脚本实际输出的目录，`old_bundle` 替换成保留的旧版解压目录：

~~~bash
sudo -i
systemctl stop gatehouse-web gatehouse-ssh gatehouse-core
backup=/var/backups/gatehouse/upgrade-0.2.1-REPLACE_ME
old_bundle=/root/gatehouse-0.2.0

python3 - "$backup" <<'PY'
import hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1])
if (p/'INCOMPLETE').exists():raise SystemExit('Incomplete snapshot')
h=hashlib.sha256()
with (p/'snapshot.tar').open('rb') as f:
    for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
expected=json.loads((p/'manifest.json').read_text())['archive_sha256']
if h.hexdigest()!=expected:raise SystemExit('Snapshot checksum mismatch')
print('snapshot checksum OK')
PY
~~~

校验成功后，安装旧版并在停服状态恢复可信的本机快照。以 amd64 为例：

~~~bash
cd "$old_bundle"
sha256sum -c SHA256SUMS-amd64
apt-get install --allow-downgrades ./gatehouse-{core,ssh,web,cli}_0.2.0_amd64.deb ./gatehouse_0.2.0_all.deb

python3 - <<'PY'
import json,pathlib
c=json.loads(pathlib.Path('/etc/gatehouse/config.json').read_text())
for suffix in ['-wal','-shm']:
    pathlib.Path(c['data'],'gatehouse.db'+suffix).unlink(missing_ok=True)
PY

tar -xpf "$backup/snapshot.tar" -C /
systemctl daemon-reload
ghbctl doctor
systemctl start gatehouse-core gatehouse-ssh gatehouse-web
bash acceptance.sh
~~~

逐步执行并检查每一步结果；不对运行中的数据库覆盖归档，不从不可信来源恢复 root 归档。arm64 使用对应旧包与摘要。包管理、systemd 生命周期和真实目标访问仍需在部署环境验收，见 [测试状态](TEST-REPORT.md)。
