#!/usr/bin/env python3
"""Check a downloaded release bundle against its requested version and commit."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import tempfile
import tarfile

from versioning import debian_version, release_version


def verify(directory, version, commit):
    release_version(version)
    info = json.loads((directory / 'BUILD-INFO.json').read_text())
    expected = dict(version=version, package_version=debian_version(version), commit=commit,
                    channel='prerelease' if '-' in version else 'release')
    if any(info.get(k) != v for k, v in expected.items()):
        raise ValueError('Release identity differs from requested version/commit')
    for line in (directory / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split('  ', 1)
        if pathlib.Path(name).name != name or hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest:
            raise ValueError('Checksum mismatch or invalid artifact path: ' + name)
    debs = list(directory.glob('*.deb'))
    expected_names = {f'gatehouse-{part}_{expected["package_version"]}_{arch}.deb'
                      for part in ('core', 'ssh', 'web', 'cli') for arch in ('amd64', 'arm64')}
    expected_names.add(f'gatehouse_{expected["package_version"]}_all.deb')
    if {p.name for p in debs} != expected_names:
        raise ValueError('Unexpected release package set')
    for deb in debs:
        value = subprocess.check_output(['dpkg-deb', '-f', str(deb), 'Version'], text=True).strip()
        if value != expected['package_version']:
            raise ValueError('Package version mismatch: ' + deb.name)
    with tempfile.TemporaryDirectory() as temp:
        cli = directory / f'gatehouse-cli_{expected["package_version"]}_amd64.deb'
        subprocess.run(['dpkg-deb', '-x', str(cli), temp], check=True)
        actual = json.loads(subprocess.check_output([temp + '/usr/bin/ghbctl', 'version', '--json'], text=True))
        if actual != {'version': version, 'commit': commit}:
            raise ValueError('Binary version/commit mismatch')
    for suffix in ('source', 'amd64', 'arm64'):
        with tarfile.open(directory / f'gatehouse-{version}-{suffix}.tar.gz') as archive:
            path = 'gatehouse/BUILD-INFO.json' if suffix == 'source' else 'BUILD-INFO.json'
            if json.load(archive.extractfile(path)) != info:
                raise ValueError('Archive identity mismatch: ' + suffix)
    print('Release tag, binary, packages and archive identities agree.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=pathlib.Path)
    parser.add_argument('version')
    parser.add_argument('commit')
    args = parser.parse_args()
    verify(args.directory, args.version, args.commit)
