#!/usr/bin/env python3
"""Check rendered version labels, installation commands, and local link targets."""
import json
import pathlib
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

ROOT = pathlib.Path(__file__).resolve().parent.parent
SITE = ROOT / 'build/docs-site'


class Page(HTMLParser):
    def __init__(self, path):
        super().__init__()
        self.path = path
        self.text = []
        self.buttons = []

    def handle_data(self, data):
        self.text.append(data)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a' and 'md-button' in attrs.get('class', '').split():
            self.buttons.append(attrs.get('href'))
        for key in ('href', 'src'):
            url = urlsplit(attrs.get(key, ''))
            if url.scheme or url.netloc or not url.path or url.path.startswith('/'):
                continue
            target = (self.path.parent / unquote(url.path)).resolve()
            if not target.exists():
                raise ValueError(f'{self.path.relative_to(SITE)}: missing {url.path}')


def main():
    metadata = json.loads((ROOT / 'build/docs-metadata.json').read_text())
    pages = {}
    for path in SITE.rglob('*.html'):
        page = Page(path)
        page.feed(path.read_text(encoding='utf-8'))
        if '{{ docs_' in ''.join(page.text) or '{{ download_' in ''.join(page.text):
            raise ValueError(f'{path}: unexpanded version token')
        pages[path.relative_to(SITE).as_posix()] = page
    home = pages['index.html']
    if metadata['docs_version'] not in ''.join(home.text):
        raise ValueError('Homepage does not show the CI version')
    if 'quickstart/' not in home.buttons:
        raise ValueError('Homepage quick-start button did not render')
    installation = ''.join(pages['installation/index.html'].text)
    if "GATEHOUSE_VERSION='" + metadata['download_version'] + "'" not in installation:
        raise ValueError('Installation command does not use the download version')
    development = ''.join(pages['development/index.html'].text)
    if 'dist/' + metadata['docs_version'] + '/' not in development:
        raise ValueError('Development output directory does not use the CI version')
    print(f'Checked {len(pages)} HTML pages, version fields, buttons and local links.')


if __name__ == '__main__':
    main()
