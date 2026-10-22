#!/usr/bin/env python3
"""Run the shipped native CLI through init/TLS/backup/restore/recovery."""
import json,os,pathlib,secrets,ssl,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parent.parent
BIN=ROOT/'build/amd64/gatehouse-cli/usr/bin/ghbctl'
def run(*a,ok=True):
 p=subprocess.run([str(x) for x in a],capture_output=True,text=True,timeout=30)
 if ok and p.returncode:raise AssertionError((a,p.stdout,p.stderr))
 return p
with tempfile.TemporaryDirectory(prefix='gatehouse-cli-') as td:
 t=pathlib.Path(td);data=t/'data';cfg=t/'config.json';cert=t/'cert.pem';key=t/'key.pem'
 run('ssh-keygen','-q','-t','ed25519','-N','','-f',t/'owner')
 run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-keyout',key,'-out',cert)
 args=['--user','owner','--public-key',t/'owner.pub','--public-host','127.0.0.1','--web-url','https://127.0.0.1:8443','--tls-cert',cert,'--tls-key',key]
 bad=run(BIN,'init','--config',t/'bad.json','--data',t/'bad-data','--run',t/'bad-run',*args,'--web-url','https://wrong.example',ok=False)
 assert bad.returncode and not (t/'bad-data/master.key').exists()
 run(BIN,'init','--config',cfg,'--data',data,'--run',t/'run',*args)
 c=json.loads(cfg.read_text());first=c['tls_key'];assert first!=str(key) and pathlib.Path(first).is_file()
 before=(data/'host.pub').read_bytes()
 run(BIN,'tls','--config',cfg,'--tls-cert',cert,'--tls-key',key)
 c=json.loads(cfg.read_text());assert c['tls_key']!=first;assert pathlib.Path(first).is_file()
 # Doctor must genuinely probe the environment, so its total result may be
 # failure here. Cryptographic/file checks still must pass.
 p=run(BIN,'doctor','--config',cfg,ok=False);checks=json.loads(p.stdout)
 mandatory={'configuration','master-key','ssh-host-key','https-certificate','private-file:master.key','private-file:host.key','private-file:gatehouse.db'}
 assert mandatory.issubset({x['name'] for x in checks})
 assert all(x['ok'] for x in checks if x['name'] in mandatory),checks
 pw=t/'password';pw.write_text(secrets.token_urlsafe(32)+'\n');pw.chmod(0o600)
 backup=t/'backup.ghb';master=t/'exported-master'
 run(BIN,'backup','--config',cfg,'--file',backup,'--passphrase-file',pw)
 run(BIN,'export-master','--config',cfg,'--file',master)
 assert master.read_bytes()==(data/'master.key').read_bytes() and master.stat().st_mode&0o777==0o600
 run(BIN,'restore','--config',cfg,'--file',backup,'--passphrase-file',pw)
 assert before==(data/'host.pub').read_bytes()
 run(BIN,'recover-owner','--config',cfg,'--user','owner','--public-key',t/'owner.pub')
 print(json.dumps({'native_cli_init':'passed','invalid_tls_before_key_creation':'passed','tls_pair_rotation':'passed','doctor_key_and_cert_checks':'passed','encrypted_backup_restore':'passed','independent_master_export':'passed','offline_owner_recovery':'passed','deployment_doctor_failures':[x['name'] for x in checks if not x['ok']]},ensure_ascii=False))
