#!/bin/bash
# Run on the actual destination after initialization, not inside an unprivileged container.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo '请使用 sudo bash acceptance.sh'; exit 1; }
[ -d /run/systemd/system ] || { echo '目标系统未运行 systemd'; exit 1; }
ghbctl doctor
systemctl enable --now gatehouse-core.service gatehouse-ssh.service gatehouse-web.service
for attempt in {1..100}; do
 if ghbctl status; then break; fi
 [ "$attempt" -lt 100 ] || { echo '核心未就绪'; exit 1; }
 sleep 0.2
done
for service in core ssh web; do systemctl is-active --quiet "gatehouse-$service.service"; done
python3 - <<'PY'
import json,os,pwd,socket,ssl,subprocess
c=json.load(open('/etc/gatehouse/config.json'))
# Actually attempt local admin access with an ingress UID. Root's successful
# ghbctl status above does not prove this negative check.
for role in ('ssh','web'):
 code='import socket; s=socket.socket(socket.AF_UNIX); s.connect('+repr(c['run']+'/admin.sock')+'); s.sendall(b"GET /status HTTP/1.0\\r\\n\\r\\n"); print(s.recv(4096))'
 result=subprocess.run(['runuser','-u','gatehouse-'+role,'--','python3','-c',code],capture_output=True,text=True)
 if result.returncode==0:raise SystemExit('FAIL: ingress UID reached admin socket')
 if 'PermissionError' not in result.stderr:raise SystemExit('FAIL: unexpected admin isolation failure: '+result.stderr)
# Verify unprivileged account cannot replace any RPC socket.
code='import os; src='+repr(c['run']+'/web.sock')+'; dst='+repr(c['run']+'/web.sock.forbidden')+'; os.rename(src,dst); os.rename(dst,src)'
r=subprocess.run(['runuser','-u','gatehouse-ssh','--','python3','-c',code],capture_output=True,text=True)
if r.returncode==0:raise SystemExit('FAIL: ingress can replace socket')
if 'PermissionError' not in r.stderr:raise SystemExit('FAIL: unexpected directory isolation failure: '+r.stderr)
for role,endpoint in (('ssh','web'),('web','ssh')):
 code="""import socket
s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect(PATH)
try:
 s.sendall(PAYLOAD);r=s.recv(1024)
 if r:raise SystemExit('wrong UID received a response')
except (ConnectionResetError,BrokenPipeError):pass
print('peer denied')
""".replace('PATH',repr(c['run']+'/'+endpoint+'.sock')).replace('PAYLOAD',repr((json.dumps({'Remote':'127.0.0.1:1234'})+'\nSSH-2.0-GatehouseProbe\r\n').encode() if endpoint=='ssh' else b'GET / HTTP/1.0\r\n\r\n'))
 result=subprocess.run(['runuser','-u','gatehouse-'+role,'--','python3','-c',code],capture_output=True,text=True)
 if result.returncode or result.stdout.strip()!='peer denied':raise SystemExit('FAIL: cross-UID peer check '+result.stderr+result.stdout)
print('PASS: service startup, root management socket, ingress filesystem isolation, cross-UID SO_PEERCRED rejection')
PY
echo '本机部署检查通过。接下来须按 README 验证一次真实管理员 SSH、Web token、目标连接及临时账号使用；脚本不代替这些业务验收。'
