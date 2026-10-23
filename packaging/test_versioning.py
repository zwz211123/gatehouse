#!/usr/bin/env python3
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from versioning import resolve, release_version, debian_version


class Versions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        env = patch.dict(os.environ, {'GATEHOUSE_VERSION': '', 'GATEHOUSE_COMMIT': '', 'SOURCE_DATE_EPOCH': ''})
        env.start()
        self.addCleanup(env.stop)

    def test_release_and_debian_order(self):
        for value in ('0.3.0', '0.3.0-rc.1', '12.0.1-alpha.9'):
            self.assertEqual(release_version(value), value)
        for value in ('v0.3.0', '01.3.0', '0.3', '0.3.0-01', '0.3.0+x', '0.3.0\n', '0.3.0;echo x'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                release_version(value)
        pre = debian_version('0.3.0-rc.1')
        self.assertEqual(pre, '0.3.0~rc.1')
        subprocess.run(['dpkg', '--compare-versions', pre, 'lt', '0.3.0'], check=True)

    def test_development_and_injected_release(self):
        self.assertEqual(resolve(self.root)['version'], 'dev')
        commit = 'a' * 40
        with patch.dict(os.environ, {'GATEHOUSE_COMMIT': commit}):
            self.assertEqual(resolve(self.root)['version'], 'dev-' + 'a' * 12)
            self.assertEqual(resolve(self.root, '0.3.0')['version'], '0.3.0')

    def test_archive_survives_without_git(self):
        with patch.dict(os.environ, {'GATEHOUSE_COMMIT': 'b' * 40, 'SOURCE_DATE_EPOCH': '12345'}):
            info = resolve(self.root, '0.3.0-rc.1')
        (self.root / 'BUILD-INFO.json').write_text(json.dumps(info))
        self.assertEqual(resolve(self.root), info)
        info['package_version'] = '0.3.0'
        (self.root / 'BUILD-INFO.json').write_text(json.dumps(info))
        with self.assertRaises(ValueError):
            resolve(self.root)

    def test_incorrect_commit_fails(self):
        with patch.dict(os.environ, {'GATEHOUSE_COMMIT': '$(touch bad)'}), self.assertRaises(ValueError):
            resolve(self.root)


if __name__ == '__main__':
    unittest.main()
