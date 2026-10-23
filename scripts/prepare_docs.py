#!/usr/bin/env python3
"""Stage public documentation without duplicating the root Markdown sources."""
import pathlib
import json
import os
import posixpath
import re
import shutil
import sys
from urllib.parse import urlsplit, urlunsplit

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'packaging'))
from versioning import resolve, release_version
OUTPUT = ROOT / 'build' / 'docs-source'
REPO = 'https://github.com/zwz211123/gatehouse/blob/main/'
ROOT_PAGES = {
    'DESIGN.md': 'architecture.md',
    'IMPLEMENTATION.md': 'implementation.md',
    'UPGRADE.md': 'upgrade.md',
    'SECURITY.md': 'security.md',
    'CONTRIBUTING.md': 'contributing.md',
    'TEST-REPORT.md': 'test-report.md',
    'CHANGELOG.md': 'changelog.md',
}


def metadata():
    """Consume the build identity supplied by Release CI, with a dev fallback."""
    supplied = os.environ.get('DOCS_VERSION') or None
    info = resolve(ROOT, version=supplied)
    version = info['version']
    channel = os.environ.get('DOCS_CHANNEL') or 'development'
    if channel not in ('development', 'release', 'prerelease'):
        raise ValueError('Unknown documentation channel')
    if channel != 'development' and (not supplied or info['channel'] != channel):
        raise ValueError('Published documentation needs an explicit matching release channel')
    stable_version = ''
    release_path = ROOT / 'build/latest-release.json'
    if release_path.exists():
        release = json.loads(release_path.read_text(encoding='utf-8'))
        candidate = release.get('tag_name', '').removeprefix('v')
        assets = {a.get('name') for a in release.get('assets', [])}
        try:
            release_version(candidate)
            valid = '-' not in candidate
        except ValueError:
            valid = False
        if (not release.get('draft') and not release.get('prerelease')
                and valid
                and f'gatehouse-{candidate}-amd64.tar.gz' in assets):
            stable_version = candidate
    download_version = version if channel == 'release' else (stable_version or version)
    labels = {'development': '开发版 / 未发布', 'release': '正式发布版', 'prerelease': '预发布版'}
    notice = f'本文档对应 **{version}（{labels[channel]}）**。'
    if channel == 'development':
        notice += ' 内容来自本次 CI 检出的源码，不代表该版本已有 Release 安装包。'
    if channel == 'prerelease':
        notice += ' 这是预发布文档；默认安装示例仍优先使用最新正式发布包。'
    if stable_version or channel == 'release':
        download_notice = f'以下示例使用已发布的 **{download_version}** amd64 安装包。'
        if download_version != version:
            download_notice += f' 本文档源码版本为 {version}，新增功能可能尚不包含在该安装包中。'
    else:
        download_notice = (f'当前未确认可用的正式发布安装包。以下以本次源码版本 **{version}** 的'
                           ' amd64 构建产物为例，请先按[开发与构建](development.md)生成安装包；'
                           '不要假定 Releases 已提供这个文件。')
    return {'docs_version': version, 'download_version': download_version,
            'docs_notice': notice, 'download_notice': download_notice,
            'docs_channel': channel}


def main():
    values = metadata()
    pages = {p.relative_to(ROOT).as_posix(): p.relative_to(ROOT / 'docs').as_posix()
             for p in sorted((ROOT / 'docs').rglob('*.md'))}
    pages.update(ROOT_PAGES)
    if OUTPUT.exists():
        shutil.rmtree(OUTPUT)
    OUTPUT.mkdir(parents=True)
    for source, destination in pages.items():
        def rewrite(match):
            target = urlsplit(match.group(2))
            if target.scheme or target.netloc or not target.path:
                return match.group(0)
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(source), target.path))
            if resolved in pages:
                link = posixpath.relpath(pages[resolved], posixpath.dirname(destination) or '.')
            elif (ROOT / resolved).is_file() and not resolved.startswith('../'):
                link = REPO + resolved
            else:
                raise ValueError(f'{source}: missing link target {target.path}')
            return f'[{match.group(1)}](' + urlunsplit(('', '', link, target.query, target.fragment)) + ')'

        # Expand explicit version tokens only; preserve historical version literals.
        text = (ROOT / source).read_text(encoding='utf-8')
        for key, value in values.items():
            text = text.replace('{{ ' + key + ' }}', value)
        if re.search(r'{{\s*(?:docs_|download_)[a-z_]+\s*}}', text):
            raise ValueError(f'{source}: unknown documentation version token')
        # Link rewriting must not modify code samples.
        chunks = re.split(r'(^[ \t]*(?:`{3,}|~{3,})[^\n]*\n.*?^[ \t]*(?:`{3,}|~{3,})[ \t]*$)',
                          text, flags=re.MULTILINE | re.DOTALL)
        text = ''.join(chunk if i % 2 else re.sub(r'\[([^\]\n]+)\]\(([^\s)]+)\)', rewrite, chunk)
                       for i, chunk in enumerate(chunks))
        output = OUTPUT / destination
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding='utf-8')
    if (ROOT / 'docs' / 'assets').exists():
        shutil.copytree(ROOT / 'docs' / 'assets', OUTPUT / 'assets')
    (ROOT / 'build/docs-metadata.json').write_text(
        json.dumps(values, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'Staged {len(pages)} documentation pages in {OUTPUT.relative_to(ROOT)}')


if __name__ == '__main__':
    main()
