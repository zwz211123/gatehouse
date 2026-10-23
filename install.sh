#!/bin/bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
[ "$(id -u)" = 0 ] || { echo '请使用 sudo bash install.sh'; exit 1; }
arch=$(dpkg --print-architecture)
case "$arch" in amd64|arm64);; *) echo "暂不支持架构：$arch";exit 1;; esac
[ -d /run/systemd/system ] || { echo '需要正在运行的 systemd；未修改系统。'; exit 1; }
sha256sum -c "SHA256SUMS-$arch"
shopt -s nullglob
cli_packages=(./gatehouse-cli_*_"$arch".deb)
[ "${#cli_packages[@]}" = 1 ] || { echo '需要且只能有一个匹配架构的 CLI 包'; exit 1; }
package_version=$(dpkg-deb -f "${cli_packages[0]}" Version)
packages=()
for part in core ssh web cli; do
 files=(./gatehouse-"$part"_*_"$arch".deb)
 [ "${#files[@]}" = 1 ] || { echo "组件包数量错误：$part"; exit 1; }
 [ "$(dpkg-deb -f "${files[0]}" Package)" = "gatehouse-$part" ] &&
 [ "$(dpkg-deb -f "${files[0]}" Version)" = "$package_version" ] &&
 [ "$(dpkg-deb -f "${files[0]}" Architecture)" = "$arch" ] || { echo '组件版本或架构不一致'; exit 1; }
 packages+=("${files[0]}")
done
meta_packages=(./gatehouse_*_all.deb)
[ "${#meta_packages[@]}" = 1 ] || { echo '元包数量错误'; exit 1; }
[ "$(dpkg-deb -f "${meta_packages[0]}" Package)" = gatehouse ] &&
[ "$(dpkg-deb -f "${meta_packages[0]}" Version)" = "$package_version" ] &&
[ "$(dpkg-deb -f "${meta_packages[0]}" Architecture)" = all ] || { echo '元包版本不一致'; exit 1; }
packages+=("${meta_packages[0]}")
config=/etc/gatehouse/config.json
backup=''
checkdir=$(mktemp -d /root/.gatehouse-upgrade-check-XXXXXX)
cleanup() { rm -rf -- "$checkdir"; }
trap cleanup EXIT
failure() {
 echo '安装或校验失败，Gatehouse 保持停止。不要执行 init。' >&2
 if [ -n "$backup" ]; then echo "升级快照：$backup；请按 UPGRADE.md 回退。" >&2; fi
 systemctl stop gatehouse-web.service gatehouse-ssh.service gatehouse-core.service || true
}
trap 'failure' ERR
if [ -f "$config" ]; then
 command -v python3 >/dev/null || { echo '升级前需要 python3；请先 apt-get install python3。';exit 1; }
 echo '即将停止 Gatehouse：现有连接会断开，系统原有 SSH 不受影响。'
 systemctl stop gatehouse-web.service gatehouse-ssh.service gatehouse-core.service
 # Inspect with the NEW binary before dpkg changes any installed component.
 dpkg-deb -x "${cli_packages[0]}" "$checkdir"
 "$checkdir/usr/bin/ghbctl" upgrade-check --config "$config"
 install -d -m 700 /var/backups/gatehouse
 backup=$(mktemp -d /var/backups/gatehouse/upgrade-${package_version}-XXXXXXXX)
 rmdir -- "$backup"
 python3 upgrade_state.py snapshot "$config" "$backup"
 echo "快照含完整密钥，请保留在 root 专用目录：$backup"
fi
apt-get install python3 "${packages[@]}"
if [ -f "$config" ]; then
 ghbctl upgrade-check --config "$config"
 python3 upgrade_state.py verify "$config" "$backup"
 ghbctl doctor
 systemctl restart gatehouse-core.service
 systemctl start gatehouse-ssh.service gatehouse-web.service
 for attempt in {1..100}; do
  if ghbctl status; then break; fi
  [ "$attempt" -lt 100 ] || { echo '核心未就绪'; false; }
  sleep 0.2
 done
 echo "$package_version 升级完成。原配置已保留。升级快照：$backup"
else
 echo '组件已安装。首次部署按 README.md 执行 ghbctl init，再执行 sudo bash acceptance.sh。'
fi
