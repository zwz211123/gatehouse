#!/usr/bin/env python3
"""Resolve build identity once; never infer a release from a source constant."""
import argparse
import json
import os
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
SEMVER = r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?'


def release_version(value):
    match = re.fullmatch(SEMVER, value)
    if not match or (match[4] and any(p.isdigit() and len(p) > 1 and p[0] == '0' for p in match[4].split('.'))):
        raise ValueError('Expected MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-prerelease (no build metadata)')
    return value


def debian_version(version):
    release_version(version)
    base, sep, pre = version.partition('-')
    return base + ('~' + pre if sep else '')


def git_value(root, *args):
    try:
        return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.DEVNULL, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return ''


def resolve(root=ROOT, version=None):
    root = pathlib.Path(root)
    revision = git_value(root, 'rev-parse', 'HEAD') if (root / '.git').exists() else ''
    archived = {}
    if not revision and (root / 'BUILD-INFO.json').is_file():
        archived = json.loads((root / 'BUILD-INFO.json').read_text())
    commit = os.environ.get('GATEHOUSE_COMMIT') or revision or archived.get('commit', 'unknown')
    if commit != 'unknown' and not re.fullmatch(r'[0-9a-f]{40,64}', commit):
        raise ValueError('Invalid source commit')
    if revision and commit != revision:
        raise ValueError('Build commit differs from checked-out source')
    supplied = version if version is not None else os.environ.get('GATEHOUSE_VERSION', '')
    if supplied:
        value = release_version(supplied)
    else:
        value = archived.get('version') or ('dev-' + commit[:12] if commit != 'unknown' else 'dev')
    if value.startswith('dev'):
        expected = 'dev-' + commit[:12] if commit != 'unknown' else 'dev'
        if value != expected:
            raise ValueError('Invalid development version')
        package = '0~dev.' + (commit[:12] if commit != 'unknown' else 'local')
        channel = 'development'
    else:
        package = debian_version(value)
        channel = 'prerelease' if '-' in value else 'release'
    epoch = os.environ.get('SOURCE_DATE_EPOCH') or (git_value(root, 'show', '-s', '--format=%ct', 'HEAD') if revision else '') or str(archived.get('source_date_epoch', 0))
    if not epoch.isdigit():
        raise ValueError('Invalid SOURCE_DATE_EPOCH')
    info = dict(version=value, package_version=package, commit=commit, channel=channel, source_date_epoch=int(epoch))
    if archived and not supplied and any(archived.get(k) != info[k] for k in ('version', 'package_version', 'commit', 'channel')):
        raise ValueError('Invalid archived build identity')
    return info


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tag')
    parser.add_argument('--prerelease', choices=['true', 'false'])
    parser.add_argument('--output', type=pathlib.Path)
    args = parser.parse_args()
    version = None
    if args.tag is not None:
        if not args.tag.startswith('v'):
            raise ValueError('Release tag must begin with v')
        version = release_version(args.tag[1:])
        if args.prerelease is not None and (args.prerelease == 'true') != ('-' in version):
            raise ValueError('Prerelease switch must match the tag suffix')
    info = resolve(version=version)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(info, indent=2) + '\n')
    print(json.dumps(info))


if __name__ == '__main__':
    main()
