#!/usr/bin/env python3
"""Build static amd64/arm64 executables and Debian packages; no host installs."""
import hashlib,json,os,pathlib,shutil,subprocess,tarfile,sys
ROOT=pathlib.Path(__file__).resolve().parent.parent
from versioning import resolve
INFO=resolve()
VERSION=INFO['version']
PACKAGE_VERSION=INFO['package_version']
INFO_PATH=ROOT/'build/version.json'
INFO_PATH.parent.mkdir(parents=True,exist_ok=True)
if '--repack-only' in sys.argv:
    if not INFO_PATH.exists() or json.loads(INFO_PATH.read_text())!=INFO:
        raise SystemExit('Repack identity differs from compiled artifacts; rebuild first')
else:
    INFO_PATH.write_text(json.dumps(INFO,indent=2)+'\n')
OUT=ROOT/'dist'/VERSION
GO=os.environ.get('GATEHOUSE_GO','go')
REPACK='--repack-only' in sys.argv
if not REPACK:shutil.rmtree(OUT,ignore_errors=True)
OUT.mkdir(parents=True,exist_ok=True)
os.environ['SOURCE_DATE_EPOCH']=str(INFO['source_date_epoch'])
sys.path.insert(0,str(ROOT/'scripts'))
from prepare_docs import stage_offline_docs
DOCS=ROOT/'build/package-docs'
stage_offline_docs(DOCS,INFO)
def run(*args,**kw): subprocess.run(args,check=True,**kw)
def write(path,text,mode=0o644):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text);path.chmod(mode)
def control(stage,name,arch,depends,description):
    write(stage/'DEBIAN/control',f'Package: {name}\nVersion: {PACKAGE_VERSION}\nArchitecture: {arch}\nMaintainer: Gatehouse Project <gatehouse@localhost>\nDepends: {depends}\nSection: admin\nPriority: optional\nDescription: {description}\n')
def unit(part):
    user={'core':'gatehouse-core','ssh':'gatehouse-ssh','web':'gatehouse-web'}[part]
    core=part=='core'
    return f'''[Unit]
Description=Gatehouse {part}
After=network.target {' ' if core else 'gatehouse-core.service'}
{' ' if core else 'Requires=gatehouse-core.service'+chr(10)+'PartOf=gatehouse-core.service'+chr(10)+'Wants=network-online.target'}
ConditionPathExists=/etc/gatehouse/config.json

[Service]
Type=simple
User={user}
Group={'gatehouse-rpc' if core else user}
SupplementaryGroups=gatehouse-rpc
ExecStart=/usr/lib/gatehouse/ghb-{part} -config /etc/gatehouse/config.json
Restart=on-failure
RestartSec=3
TimeoutStopSec=35
KillMode=mixed
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
LimitNOFILE=8192
{'RuntimeDirectory=gatehouse'+chr(10)+'RuntimeDirectoryMode=0750'+chr(10)+'ReadWritePaths=/var/lib/gatehouse /run/gatehouse' if core else ''}

[Install]
WantedBy=multi-user.target
'''.replace('\n \n','\n')
postinst='''#!/bin/sh
set -eu
if [ "$1" = configure ]; then
 getent group gatehouse-rpc >/dev/null || addgroup --system gatehouse-rpc
 for part in core ssh web; do
  getent group "gatehouse-$part" >/dev/null || addgroup --system "gatehouse-$part"
  getent passwd "gatehouse-$part" >/dev/null || adduser --system --ingroup "gatehouse-$part" --home /nonexistent --no-create-home --shell /usr/sbin/nologin "gatehouse-$part"
  adduser "gatehouse-$part" gatehouse-rpc >/dev/null
 done
 install -d -o gatehouse-core -g gatehouse-core -m 0700 /var/lib/gatehouse
 install -d -o root -g root -m 0755 /etc/gatehouse
 if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
 if [ -f /etc/gatehouse/config.json ]; then
  echo 'Gatehouse updated; existing configuration retained. Do not run init.'
 else
  echo 'Gatehouse installed. Run ghbctl init, configure TLS and start services. Existing SSH is unchanged.'
 fi
fi
'''
for arch in ([] if REPACK else ['amd64','arm64']):
    build=ROOT/'build'/arch
    build.mkdir(parents=True,exist_ok=True)
    for part in ['core','ssh','web','cli']:
        name='gatehouse-'+part
        stage=build/name
        shutil.rmtree(stage,ignore_errors=True)
        binary=stage/('usr/bin/ghbctl' if part=='cli' else 'usr/lib/gatehouse/ghb-'+part)
        binary.parent.mkdir(parents=True,exist_ok=True)
        env=os.environ|{'CGO_ENABLED':'0','GOOS':'linux','GOARCH':arch,'GOAMD64':'v1','GOTOOLCHAIN':'local'}
        # Compile outside the archive tree: linker/copy temporary files must
        # never be picked up by dpkg-deb while the tree is being archived.
        compiled=build/('compiled-'+part)
        run(GO,'build','-trimpath','-buildvcs=false','-ldflags',f"-s -w -X main.role={part} -X github.com/zwz211123/gatehouse/internal/gh.Version={VERSION} -X github.com/zwz211123/gatehouse/internal/gh.Commit={INFO['commit']}",'-o',str(compiled),'./cmd/gatehouse',cwd=ROOT,env=env)
        shutil.copyfile(compiled,binary)
        binary.chmod(0o755)
        depends='adduser, systemd, init-system-helpers' if part=='core' else f'gatehouse-core (= {PACKAGE_VERSION}), systemd, init-system-helpers'
        control(stage,name,arch,depends,'SSH access broker '+part+' component')
        docs=stage/'usr/share/doc'/name
        docs.mkdir(parents=True,exist_ok=True)
        shutil.copy(DOCS/'README.md',docs/'README.md')
        shutil.copy(ROOT/'LICENSE',docs/'copyright')
        for doc in ['README.en.md','UPGRADE.md','DESIGN.md','IMPLEMENTATION.md','TEST-REPORT.md','CHANGELOG.md','SECURITY.md','CONTRIBUTING.md']:
            shutil.copy(DOCS/doc,docs/doc)
        shutil.copytree(DOCS/'docs',docs/'docs',dirs_exist_ok=True)
        if (ROOT/'THIRD-PARTY-LICENSES.txt').exists():shutil.copy(ROOT/'THIRD-PARTY-LICENSES.txt',docs/'THIRD-PARTY-LICENSES.txt')
        if part!='cli':
            write(stage/f'lib/systemd/system/gatehouse-{part}.service',unit(part))
            write(stage/'DEBIAN/prerm',f'''#!/bin/sh
set -eu
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then deb-systemd-invoke stop gatehouse-{part}.service || true; fi
''',0o755)
            write(stage/'DEBIAN/postrm',f'''#!/bin/sh
set -eu
if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
if [ "$1" = purge ]; then deb-systemd-helper purge gatehouse-{part}.service >/dev/null || true; fi
'''+('''if [ "$1" = purge ]; then
 rm -rf -- /var/lib/gatehouse /etc/gatehouse
fi
''' if part=='core' else ''),0o755)
        if part!='cli':
            service_postinst=(postinst if part=='core' else '#!/bin/sh\nset -eu\n')+f'''
if [ "$1" = configure ]; then
 deb-systemd-helper unmask gatehouse-{part}.service >/dev/null || true
 # Keep explicit enable/disable choices, and do not start uninitialized services.
 deb-systemd-helper update-state gatehouse-{part}.service >/dev/null || true
 if [ -n "${{2:-}}" ] && [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  deb-systemd-invoke try-restart gatehouse-{part}.service || true
 fi
fi
'''
            write(stage/'DEBIAN/postinst',service_postinst,0o755)
        if part=='core': 
            shutil.copy(ROOT/'config.example.json',docs/'config.example.json')
        run('dpkg-deb','--root-owner-group','--threads-max=2','-Zxz','--build',str(stage),str(OUT/f'{name}_{PACKAGE_VERSION}_{arch}.deb'))
meta=ROOT/'build'/'meta'
shutil.rmtree(meta,ignore_errors=True)
control(meta,'gatehouse','all',', '.join(f'gatehouse-{p} (= {PACKAGE_VERSION})' for p in ['core','ssh','web','cli']),'Complete Gatehouse SSH access broker')
run('dpkg-deb','--root-owner-group','--threads-max=2','-Zxz','--build',str(meta),str(OUT/f'gatehouse_{PACKAGE_VERSION}_all.deb'))
for arch in ['amd64','arm64']:
    files=sorted(OUT.glob(f'*_{PACKAGE_VERSION}_{arch}.deb'))+[OUT/f'gatehouse_{PACKAGE_VERSION}_all.deb']
    manifest=''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in files)
    sha=OUT/f'SHA256SUMS-{arch}';sha.write_text(manifest)
    with tarfile.open(OUT/f'gatehouse-{VERSION}-{arch}.tar.gz','w:gz') as tar:
        for p in files+[sha,ROOT/'README.md',ROOT/'README.en.md',ROOT/'CONTRIBUTING.md',ROOT/'LICENSE',ROOT/'SECURITY.md',ROOT/'DESIGN.md',ROOT/'IMPLEMENTATION.md',ROOT/'TEST-REPORT.md',ROOT/'install.sh',ROOT/'acceptance.sh',ROOT/'CHANGELOG.md',ROOT/'UPGRADE.md',ROOT/'packaging/upgrade_state.py']+([ROOT/'VALIDATION.json'] if (ROOT/'VALIDATION.json').is_file() else []):
            tar.add(DOCS/p.name if p.suffix=='.md' else p,arcname=p.name)
        tar.add(DOCS/'docs',arcname='docs')
        tar.add(INFO_PATH,arcname='BUILD-INFO.json')
with tarfile.open(OUT/f'gatehouse-{VERSION}-source.tar.gz','w:gz') as tar:
    tar.add(INFO_PATH,arcname='gatehouse/BUILD-INFO.json')
    # Include project sources explicitly. Never archive arbitrary untracked
    # instance files, credentials, environment files or generated artifacts.
    source_roots=['cmd','internal','packaging','tests','scripts','docs','.github']
    source_files=['README.md','README.en.md','DESIGN.md','IMPLEMENTATION.md','TEST-REPORT.md','UPGRADE.md','CHANGELOG.md','CONTRIBUTING.md','SECURITY.md','LICENSE','THIRD-PARTY-LICENSES.txt','go.mod','go.sum','package.json','package-lock.json','mkdocs.yml','requirements-docs.txt','config.example.json','install.sh','acceptance.sh','.gitignore','.gitattributes']
    candidates=[ROOT/name for name in source_files]
    for name in source_roots:candidates.extend((ROOT/name).rglob('*'))
    if (ROOT/'.git').exists():
        tracked=subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0')
        candidates=[ROOT/name for name in tracked if name]
    allowed_suffixes={'.go','.py','.cjs','.js','.json','.md','.html','.css','.yml','.yaml','.sh'}
    for p in sorted(set(candidates)):
        rel=p.relative_to(ROOT)
        if not p.is_file() or p.is_symlink() or any(part in ['build','dist','node_modules','__pycache__','.git'] for part in rel.parts):continue
        if len(rel.parts)==1 and str(rel) not in source_files:continue
        if len(rel.parts)>1 and rel.parts[0] not in source_roots:continue
        if len(rel.parts)>1 and p.suffix not in allowed_suffixes:continue
        tar.add(p,arcname='gatehouse/'+str(rel))
shutil.copyfile(INFO_PATH,OUT/'BUILD-INFO.json')
(OUT/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(OUT.iterdir()) if p.name!='SHA256SUMS'))
print('Artifacts:',OUT)
