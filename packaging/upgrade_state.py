#!/usr/bin/env python3
"""Offline 0.2.x identity migration: snapshot and verify, never rewrite records.

The snapshot contains master/private keys and is intentionally root-only. It is
independent of the user-facing encrypted backup format and includes WAL files.
"""
import contextlib,fcntl,hashlib,json,os,pathlib,sqlite3,sys,tarfile,urllib.parse

def require(condition,message):
    if not condition:raise ValueError(message)

def digest(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()

def adopt_sidecars(config):
    # SQLite WAL readers may create these files even in mode=ro.
    data=pathlib.Path(config['data']);owner=data.stat()
    for name in ['.core.lock','gatehouse.db-wal','gatehouse.db-shm']:
        path=data/name
        if path.is_symlink():raise ValueError('Unexpected symlink in data directory')
        if path.exists():os.chown(path,owner.st_uid,owner.st_gid);os.chmod(path,0o600)

@contextlib.contextmanager
def locked(config):
    flags=os.O_RDWR|os.O_CREAT|os.O_CLOEXEC|os.O_NOFOLLOW
    fd=os.open(pathlib.Path(config['data'])/'.core.lock',flags,0o600)
    acquired=False
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        acquired=True
        yield
    finally:
        try:
            if acquired:adopt_sidecars(config)
        finally:os.close(fd)

def state(config_path):
    config=json.loads(config_path.read_text());data=pathlib.Path(config['data'])
    uri='file:'+urllib.parse.quote(str(data/'gatehouse.db'),safe='/')+'?mode=ro'
    with contextlib.closing(sqlite3.connect(uri,uri=True)) as db:
        require(db.execute('PRAGMA integrity_check').fetchall()==[('ok',)],'SQLite integrity check failed')
        require(db.execute('SELECT MAX(version) FROM schema_migrations').fetchone()==(1,),'Unsupported database schema')
        records=db.execute('SELECT kind,id,data,revision FROM records ORDER BY kind,id').fetchall()
        audit=db.execute('SELECT seq,data FROM audits ORDER BY seq').fetchall()
        h=hashlib.sha256(json.dumps([records,audit],ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
    paths=[config_path,data/'master.key',data/'host.key',data/'host.pub']
    for field in ['tls_cert','tls_key']:
        if config.get(field):paths.append(pathlib.Path(config[field]))
    require(len((data/'master.key').read_bytes())==32,'Invalid master key')
    return {'schema':1,'record_count':len(records),'audit_count':len(audit),'logical_sha256':h,'files':{str(p):digest(p) for p in paths}}

def main():
    operation,config_arg,destination=sys.argv[1:]
    config_path=pathlib.Path(config_arg).resolve();config=json.loads(config_path.read_text());backup=pathlib.Path(destination).resolve()
    require(operation in ['snapshot','verify'],'Unknown operation')
    require(os.geteuid()==0,'Requires root')
    with locked(config):
        current=state(config_path)
        adopt_sidecars(config)
        if operation=='verify':
            require(not (backup/'INCOMPLETE').exists(),'Incomplete snapshot')
            expected=json.loads((backup/'manifest.json').read_text())
            require(current==expected['state'],'Configuration or database changed during upgrade; services remain stopped')
            require(digest(backup/'snapshot.tar')==expected['archive_sha256'],'Snapshot checksum mismatch')
            print('升级后数据一致：记录、修订号、审计、主密钥、SSH 身份、配置与 TLS 未改变。')
            return
        require(backup!=config_path.parent and config_path.parent not in backup.parents,'Snapshot must be outside configuration directory')
        require(backup!=pathlib.Path(config['data']) and pathlib.Path(config['data']) not in backup.parents,'Snapshot must be outside data directory')
        backup.mkdir(mode=0o700,parents=True,exist_ok=False)
        os.chmod(backup,0o700)
        archive=backup/'snapshot.tar'
        try:
            with archive.open('xb') as f:
                os.fchmod(f.fileno(),0o600)
                with tarfile.open(fileobj=f,mode='w',dereference=True) as tar:
                    paths=[config_path.parent,pathlib.Path(config['data']),pathlib.Path('/usr/lib/gatehouse'),pathlib.Path('/usr/bin/ghbctl')]
                    paths.extend(pathlib.Path('/lib/systemd/system/gatehouse-'+p+'.service') for p in ['core','ssh','web'])
                    paths.extend(pathlib.Path(config[k]) for k in ['tls_cert','tls_key'] if config.get(k))
                    roots=[]
                    for path in paths:
                        path=path.absolute()
                        if not path.exists() or any(path==p or p in path.parents for p in roots):continue
                        roots.append(path)
                        tar.add(path,arcname=str(path).lstrip('/'))
                f.flush();os.fsync(f.fileno())
            manifest={'format':'gatehouse-upgrade-v1','from':'0.2.x','to':'0.2.1','state':current,'archive_sha256':digest(archive)}
            with (backup/'manifest.json').open('x') as f:
                os.fchmod(f.fileno(),0o600);json.dump(manifest,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
            # Ensure the stopped source did not change while it was copied.
            require(state(config_path)==current,'Source changed during snapshot')
        except BaseException:
            # Never present an incomplete checkpoint as a recoverable snapshot.
            (backup/'INCOMPLETE').touch(mode=0o600)
            raise
        print('升级快照已生成：'+str(backup))

if __name__=='__main__':
    try:main()
    except Exception as e:
        print('升级保护检查失败：'+str(e),file=sys.stderr);sys.exit(1)
