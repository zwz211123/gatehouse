#!/usr/bin/env python3
"""Regression checks for CI-injected versions and historical documentation."""
import json
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import prepare_docs


class DocumentationVersionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        (self.root / 'internal/gh').mkdir(parents=True)
        (self.root / 'internal/gh/config.go').write_text('const Version = "7.8.9"\n')
        (self.root / 'build').mkdir()
        self.root_patch = patch.object(prepare_docs, 'ROOT', self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.env_patch = patch.dict(os.environ, {'DOCS_VERSION': '', 'DOCS_CHANNEL': '', 'GATEHOUSE_VERSION': '', 'GATEHOUSE_COMMIT': '', 'SOURCE_DATE_EPOCH': ''})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def release(self, **overrides):
        release = {'tag_name': 'v7.8.8', 'draft': False, 'prerelease': False,
                   'assets': [{'name': 'gatehouse-7.8.8-amd64.tar.gz'}]}
        release.update(overrides)
        (self.root / 'build/latest-release.json').write_text(json.dumps(release))

    def test_development_version_does_not_invent_release(self):
        data = prepare_docs.metadata()
        self.assertEqual(data['docs_version'], 'dev')
        self.assertIn('开发版 / 未发布', data['docs_notice'])
        self.assertIn('当前未确认', data['download_notice'])

    def test_development_download_uses_existing_stable_bundle(self):
        self.release()
        data = prepare_docs.metadata()
        self.assertEqual(data['download_version'], '7.8.8')
        self.assertIn('新增功能可能尚不包含', data['download_notice'])

    def test_release_version_has_no_source_constant_dependency(self):
        (self.root / 'internal/gh/config.go').unlink()
        with patch.dict(os.environ, {'DOCS_VERSION': '9.0.0', 'DOCS_CHANNEL': 'release'}):
            self.assertEqual(prepare_docs.metadata()['docs_version'], '9.0.0')

    def test_release_ci_version_is_used(self):
        self.release()
        with patch.dict(os.environ, {'DOCS_VERSION': '7.8.9', 'DOCS_CHANNEL': 'release'}):
            data = prepare_docs.metadata()
        self.assertEqual(data['download_version'], '7.8.9')
        self.assertIn('正式发布版', data['docs_notice'])

    def test_prerelease_keeps_stable_download(self):
        self.release()
        with patch.dict(os.environ, {'DOCS_VERSION': '7.8.9-rc.1', 'DOCS_CHANNEL': 'prerelease'}):
            data = prepare_docs.metadata()
        self.assertEqual(data['download_version'], '7.8.8')
        self.assertIn('预发布版', data['docs_notice'])

    def test_missing_bundle_draft_and_prerelease_are_not_stable_downloads(self):
        for override in ({'assets': []}, {'draft': True}, {'prerelease': True}):
            with self.subTest(override=override):
                self.release(**override)
                self.assertIn('当前未确认', prepare_docs.metadata()['download_notice'])

    def test_invalid_version_and_channel_fail(self):
        for override in ({'DOCS_VERSION': 'bad'}, {'DOCS_CHANNEL': 'release'},
                         {'DOCS_VERSION': '7.8.9', 'DOCS_CHANNEL': 'prerelease'},
                         {'DOCS_CHANNEL': 'unknown'}):
            with self.subTest(override=override), patch.dict(os.environ, override):
                with self.assertRaises(ValueError):
                    prepare_docs.metadata()

    def test_only_explicit_tokens_expand_including_code_samples(self):
        (self.root / 'docs').mkdir()
        history = 'Historical migration 0.2.0 -> 0.2.1\n'
        for name in prepare_docs.ROOT_PAGES:
            (self.root / name).write_text(history)
        (self.root / 'docs/index.md').write_text(
            '{{ docs_notice }}\n~~~bash\nVERSION={{ docs_version }}\n~~~\n' + history)
        output = self.root / 'build/docs-source'
        with patch.object(prepare_docs, 'OUTPUT', output):
            prepare_docs.main()
        text = (output / 'index.md').read_text()
        self.assertIn('VERSION=dev', text)
        self.assertIn(history, text)
        self.assertEqual((output / 'upgrade.md').read_text(), history)

    def test_offline_docs_use_package_identity_and_preserve_source_layout(self):
        docs = self.root / 'docs'
        (docs / 'assets').mkdir(parents=True)
        (docs / 'assets/style.css').write_text('body {}')
        history = 'Historical migration 0.2.0 -> 0.2.1\n'
        (self.root / 'UPGRADE.md').write_text(history)
        (self.root / 'README.md').write_text('[Install](docs/installation.md)\n')
        template = ("{{ download_notice }}\n~~~bash\n"
                    "GATEHOUSE_VERSION='{{ download_version }}'\n~~~\n"
                    '[Upgrade](../UPGRADE.md)\n')
        (docs / 'installation.md').write_text(template)
        (docs / 'index.md').write_text('{{ docs_notice }}\n')
        (docs / 'development.md').write_text('dist/{{ docs_version }}/\n')
        self.release()  # A website download hint must not affect package docs.
        for version, channel in [('9.0.0', 'release'), ('9.0.0-rc.1', 'prerelease'),
                                 ('dev-abcdef012345', 'development')]:
            with self.subTest(channel=channel):
                output = self.root / 'build/package-docs'
                prepare_docs.stage_offline_docs(output, {'version': version, 'channel': channel}, self.root)
                text = (output / 'docs/installation.md').read_text()
                self.assertIn("GATEHOUSE_VERSION='" + version + "'", text)
                self.assertIn('不表示该构建已发布到 Releases', text)
                self.assertIn('[Upgrade](../UPGRADE.md)', text)
                self.assertEqual((output / 'README.md').read_text(), '[Install](docs/installation.md)\n')
                self.assertEqual((output / 'UPGRADE.md').read_text(), history)
                self.assertEqual((output / 'docs/assets/style.css').read_text(), 'body {}')
                self.assertIn(version, (output / 'docs/index.md').read_text())
                self.assertEqual((output / 'docs/development.md').read_text(), 'dist/' + version + '/\n')
                self.assertFalse((output / 'upgrade.md').exists())
        self.assertEqual((docs / 'installation.md').read_text(), template)

    def test_offline_docs_reject_unexpanded_version_tokens(self):
        (self.root / 'docs').mkdir()
        (self.root / 'docs/index.md').write_text('{{ docs_typo }}')
        with self.assertRaises(ValueError):
            prepare_docs.stage_offline_docs(self.root / 'build/offline',
                                            {'version': '9.0.0', 'channel': 'release'}, self.root)


if __name__ == '__main__':
    unittest.main()
