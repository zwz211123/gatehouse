#!/usr/bin/env python3
import json,os,pathlib,re,subprocess,tarfile,tempfile
ROOT=pathlib.Path(__file__).resolve().parent.parent
INFO=json.loads((ROOT/'build/version.json').read_text())
VERSION=INFO['version']
PACKAGE_VERSION=INFO['package_version']
def run(*a):return subprocess.check_output(a,text=True,stderr=subprocess.STDOUT)
def check_docs(files):
    for name,body in files.items():
        assert not re.search(r'{{\s*(?:docs_|download_)[a-z_]+\s*}}',body),name
    assert "GATEHOUSE_VERSION='"+VERSION+"'" in files['docs/installation.md']
    assert VERSION in files['docs/index.md']
    assert 'dist/'+VERSION+'/' in files['docs/development.md']
    assert '[升级](UPGRADE.md)' in files['README.md']
    assert files['UPGRADE.md']==(ROOT/'UPGRADE.md').read_text()
debs=sorted((ROOT/'dist'/VERSION).glob('*.deb'));assert len(debs)==9,len(debs)
summary=[]
for deb in debs:
    fields=run('dpkg-deb','-f',str(deb),'Package','Version','Architecture');name=run('dpkg-deb','-f',str(deb),'Package').strip();arch=run('dpkg-deb','-f',str(deb),'Architecture').strip()
    assert run('dpkg-deb','-f',str(deb),'Version').strip()==PACKAGE_VERSION
    assert name in ['gatehouse','gatehouse-core','gatehouse-ssh','gatehouse-web','gatehouse-cli']
    assert arch in (['all'] if name=='gatehouse' else ['amd64','arm64'])
    depends=run('dpkg-deb','-f',str(deb),'Depends')
    if name=='gatehouse':
        for part in ['core','ssh','web','cli']:assert 'gatehouse-'+part+f' (= {PACKAGE_VERSION})' in depends
    elif name!='gatehouse-core':assert f'gatehouse-core (= {PACKAGE_VERSION})' in depends
    with tempfile.TemporaryDirectory(prefix='ghb-package-') as td:
        t=pathlib.Path(td);subprocess.run(['dpkg-deb','-R',str(deb),str(t)],check=True,stdout=subprocess.DEVNULL)
        assert not (t/'etc/gatehouse/config.json').exists(),'package would overwrite existing configuration'
        assert not (t/'var/lib/gatehouse/gatehouse.db').exists(),'package would overwrite existing database'
        assert not any(x.name.startswith('.ghb-') for x in t.rglob('*')),'linker temporary file in package'
        for script in (t/'DEBIAN').iterdir():
            if script.name in ['postinst','prerm','postrm']:subprocess.run(['sh','-n',str(script)],check=True)
        if arch!='all':
            docroot=t/'usr/share/doc'/name
            check_docs({p.relative_to(docroot).as_posix():p.read_text() for p in docroot.rglob('*.md')})
            binary=t/('usr/bin/ghbctl' if name=='gatehouse-cli' else 'usr/lib/gatehouse/ghb-'+name.split('-')[-1]);assert binary.is_file();elf=run('readelf','-h',str(binary));assert ('AArch64' if arch=='arm64' else 'Advanced Micro Devices X86-64') in elf;assert 'INTERP' not in run('readelf','-l',str(binary))
            if name=='gatehouse-cli':
                prefix=[]
                if arch=='arm64':
                    qemu=os.environ.get('GHB_QEMU')
                    if not qemu:raise RuntimeError('GHB_QEMU required for arm64 package execution')
                    prefix=[qemu]
                assert run(*prefix,str(binary),'version').strip()==VERSION
                assert json.loads(run(*prefix,str(binary),'version','--json'))=={'version':VERSION,'commit':INFO['commit']}
        summary.append({'package':name,'architecture':arch,'control':'passed','shell_syntax':'passed','elf':'static executable' if arch!='all' else 'meta package'})
for arch in ['amd64','arm64']:
    with tarfile.open(ROOT/'dist'/VERSION/f'gatehouse-{VERSION}-{arch}.tar.gz') as archive:
        check_docs({p.name:archive.extractfile(p).read().decode() for p in archive.getmembers() if p.isfile() and p.name.endswith('.md')})
print(json.dumps(summary,indent=2))
