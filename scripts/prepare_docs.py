#!/usr/bin/env python3
"""Stage public documentation without duplicating the root Markdown sources."""
import pathlib
import posixpath
import re
import shutil
from urllib.parse import urlsplit, urlunsplit

ROOT = pathlib.Path(__file__).resolve().parent.parent
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


def main():
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

        # Code samples must remain byte-for-byte unchanged.
        text = (ROOT / source).read_text(encoding='utf-8')
        chunks = re.split(r'(^[ \t]*(?:`{3,}|~{3,})[^\n]*\n.*?^[ \t]*(?:`{3,}|~{3,})[ \t]*$)',
                          text, flags=re.MULTILINE | re.DOTALL)
        text = ''.join(chunk if i % 2 else re.sub(r'\[([^\]\n]+)\]\(([^\s)]+)\)', rewrite, chunk)
                       for i, chunk in enumerate(chunks))
        output = OUTPUT / destination
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding='utf-8')
    if (ROOT / 'docs' / 'assets').exists():
        shutil.copytree(ROOT / 'docs' / 'assets', OUTPUT / 'assets')
    print(f'Staged {len(pages)} documentation pages in {OUTPUT.relative_to(ROOT)}')


if __name__ == '__main__':
    main()
