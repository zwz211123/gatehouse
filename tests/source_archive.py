#!/usr/bin/env python3
"""Verify public source archives contain tracked project files, not local state."""
import json,hashlib,pathlib,subprocess,tarfile
ROOT=pathlib.Path(__file__).resolve().parent.parent
INFO=json.loads((ROOT/'build/version.json').read_text())
VERSION=INFO['version']
PACKAGE_VERSION=INFO['package_version']
tracked=set(subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0'))
archive_path=ROOT/'dist'/VERSION/f'gatehouse-{VERSION}-source.tar.gz'
with tarfile.open(archive_path) as archive:
    names=[]
    for member in archive.getmembers():
        assert member.isfile() and member.name.startswith('gatehouse/'),member.name
        relative=member.name.removeprefix('gatehouse/')
        if relative=='BUILD-INFO.json':
            assert json.loads(archive.extractfile(member).read())==INFO
            names.append(relative)
            continue
        assert relative in tracked,'Untracked file included: '+relative
        assert not set(pathlib.PurePosixPath(relative).parts)&{'build','dist','node_modules','.git','__pycache__'},relative
        assert not relative.endswith(('.key','.pem','.db','.ghb','.pyc')),relative
        actual=archive.extractfile(member).read()
        assert hashlib.sha256(actual).digest()==hashlib.sha256((ROOT/relative).read_bytes()).digest(),relative
        names.append(relative)
    for required in ['BUILD-INFO.json','mkdocs.yml','requirements-docs.txt','packaging/versioning.py','scripts/prepare_docs.py','README.md','README.en.md','LICENSE','SECURITY.md','CONTRIBUTING.md','go.mod','package-lock.json','docs/installation.md','.github/workflows/ci.yml']:
        assert required in names,required
print('Public source archive matches tracked project sources; no generated state or private-key files included.')
