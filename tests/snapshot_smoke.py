#!/usr/bin/env python3
"""Verify offline snapshot/restore and identity retention on a schema-1 fixture."""
import contextlib,json,pathlib,sqlite3,subprocess,tempfile,tarfile,os
ROOT=pathlib.Path(__file__).resolve().parent.parent
INFO=json.loads((ROOT/'build/version.json').read_text())
VERSION=INFO['version']
PACKAGE_VERSION=INFO['package_version']
BIN=ROOT/'build/amd64/gatehouse-cli/usr/bin/ghbctl'
def run(*args,ok=True):
 p=subprocess.run([str(x) for x in args],capture_output=True,text=True,timeout=30)
 if ok and p.returncode:raise AssertionError((args,p.stdout,p.stderr))
 return p
with tempfile.TemporaryDirectory(prefix='ghb-upgrade-') as td:
 t=pathlib.Path(td);(t/'config').mkdir();cfg=t/'config/config.json';data=t/'data';backup=t/'backup'
 old=BIN;assert run(old,'version').stdout.strip()==VERSION
 run('ssh-keygen','-q','-t','ed25519','-N','','-f',t/'owner')
 run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',t/'key.pem','-out',t/'cert.pem')
 run(old,'init','--config',cfg,'--data',data,'--run',t/'run','--user','admin','--public-key',t/'owner.pub','--public-host','localhost','--web-url','https://localhost:8443','--tls-cert',t/'cert.pem','--tls-key',t/'key.pem')
 seed=sqlite3.connect(data/'gatehouse.db')
 with seed as db:
  owner=json.loads(db.execute("SELECT data FROM records WHERE kind='user'").fetchone()[0])['id']
  entries={
   ('asset','legacy-server'):{'id':'legacy-server','name':'已有服务器','host':'203.0.113.9','port':22,'enabled':True,'host_keys':['ssh-ed25519 existing-pin']},
   ('group','legacy-group'):{'id':'legacy-group','name':'运维','members':[owner]},
   ('grant','legacy-grant'):{'id':'legacy-grant','subject':owner,'actions':['shell.direct','proxy.shell'],'resources':['legacy-account'],'enabled':True,'deny':False,'depth':2,'expires':2000000000,'unknown_future':{'keep':True}},
   ('account','legacy-account'):{'id':'legacy-account','asset':'legacy-server','name':'deploy','credential':'old-reference','enabled':False},
   ('ticket','old-ticket'):{'id':'old-ticket','username':'ghp_old','state':'expired','unknown':'keep'},
  }
  for (kind,id),record in entries.items():db.execute('INSERT INTO records(kind,id,data,revision)VALUES(?,?,?,?)',(kind,id,json.dumps(record,ensure_ascii=False),7))
  db.execute('INSERT INTO audits(data) VALUES(?)',(json.dumps({'actor':owner,'action':'previous.event','result':'ok','time':1700000000}),))
 script=ROOT/'packaging/upgrade_state.py'
 run(BIN,'upgrade-check','--config',cfg)
 run('python3',script,'snapshot',cfg,backup)
 assert backup.stat().st_mode&0o777==0o700
 assert (backup/'snapshot.tar').stat().st_mode&0o777==0o600
 seed.close()
 manifest=json.loads((backup/'manifest.json').read_text());assert manifest['state']['schema']==1
 with tarfile.open(backup/'snapshot.tar') as archive:
  assert str(data/'master.key').lstrip('/') in archive.getnames()
  assert str(cfg).lstrip('/') in archive.getnames()
  assert str(pathlib.Path(json.loads(cfg.read_text())['tls_key'])).lstrip('/') in archive.getnames()
 run(BIN,'upgrade-check','--config',cfg)
 run('python3',script,'verify',cfg,backup)
 with contextlib.closing(sqlite3.connect(data/'gatehouse.db')) as db, db:db.execute("UPDATE records SET revision=revision+1 WHERE kind='asset'")
 assert run('python3','-O',script,'verify',cfg,backup,ok=False).returncode,'changed revisions not detected'
 # Recovery archive includes the actual stopped SQLite state and original identity.
 with tarfile.open(backup/'snapshot.tar') as archive:
  # Preserve WAL state as well; the old seed connection was intentionally
  # held open until snapshot creation, so committed records reside in WAL.
  names=archive.getnames()
  assert str(data/'gatehouse.db-wal').lstrip('/') in names
  for name in ['gatehouse.db','gatehouse.db-wal','gatehouse.db-shm']:
   path=data/name;path.unlink(missing_ok=True)
   member=str(path).lstrip('/')
   if member in names:path.write_bytes(archive.extractfile(member).read())
 run('python3',script,'verify',cfg,backup)
 with contextlib.closing(sqlite3.connect(data/'gatehouse.db')) as db, db:db.execute('INSERT INTO schema_migrations VALUES(2)')
 assert run(BIN,'upgrade-check','--config',cfg,ok=False).returncode,'future schema accepted'
 print(json.dumps({'fixture_version':VERSION,'new_version':run(BIN,'version').stdout.strip(),'schema_1_fixture_initialization':'passed','offline_compatibility':'passed','complete_root_only_snapshot':'passed','exact_records_revisions_audit_identity_config_tls':'passed','mutation_detection':'passed','snapshot_restore':'passed','future_schema_rejected':'passed','real_dpkg_systemd_upgrade':'not part of this snapshot test'},ensure_ascii=False))
