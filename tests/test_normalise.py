"""Tests for normalise-unraid-templates.py.

    python3 -m unittest discover -s tests
"""
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, '..', 'normalise-unraid-templates.py')


def load(src, dst):
    """Import the script fresh, with SRC/DST pointed at scratch directories."""
    argv = sys.argv
    sys.argv = ['normalise-unraid-templates.py', src, dst]
    try:
        spec = importlib.util.spec_from_file_location('normalise', SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        sys.argv = argv
    return mod


def template(body, extra='', name='Test', repo='example/app:latest', webui=''):
    return (f'<?xml version="1.0"?>\n<Container version="2">\n'
            f'  <Name>{name}</Name>\n  <Repository>{repo}</Repository>\n'
            f'  <Network>bridge</Network>\n  <WebUI>{webui}</WebUI>\n'
            f'  <ExtraParams>{extra}</ExtraParams>\n{body}</Container>\n')


def config(name, target, value, ctype='Variable', mode='', desc='', default=''):
    return (f'  <Config Name="{name}" Target="{target}" Default="{default}" Mode="{mode}" '
            f'Description="{desc}" Type="{ctype}" Display="always" Required="false" '
            f'Mask="false">{value}</Config>\n')


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = os.path.join(self.tmp, 'src')
        self.dst = os.path.join(self.tmp, 'dst')
        os.makedirs(self.src)
        os.makedirs(self.dst)
        self.m = load(self.src, self.dst)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_one(self, xml, fname='my-Test.xml'):
        path = os.path.join(self.src, fname)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(xml)
        self.m.process(path)
        with open(os.path.join(self.dst, fname), encoding='utf-8') as f:
            out = f.read()
        return out, ET.fromstring(out)


class BrLitter(Base):
    def test_real_words_survive(self):
        for text in ['br0 bridge interface', 'broker URL for MQTT', 'bring your own key',
                     'brotli level', 'Line one\nbroadcast address', 'Uses br0.',
                     'Calibre and LibreOffice', 'browserless is a web service']:
            self.assertEqual(self.m.strip_br_litter(text), text, text)

    def test_litter_removed(self):
        s = self.m.strip_br_litter
        self.assertEqual(s('brFirst line'), 'First line')
        self.assertEqual(s('One\nbr\nTwo'), 'One\n\nTwo')
        self.assertEqual(s('ends here.brNext sentence'), 'ends here.\nNext sentence')
        self.assertEqual(s('One\nbrthe next line'), 'One\nthe next line')


class PathPortNames(Base):
    def test_number_prefix_does_not_eat_label(self):
        self.assertEqual(self.m.parse_pathport('Path 4K Movies', '/m', 'Path')[2], '4K Movies')
        self.assertEqual(self.m.parse_pathport('Port 2FA', '2fa', 'Port')[2], '2FA')

    def test_numbered_prefix_still_parsed(self):
        self.assertEqual(self.m.parse_pathport('Path 04.1: Media', '/m', 'Path'), (4, 1, 'Media'))
        self.assertEqual(self.m.parse_pathport('Port 2: Web UI', '80', 'Port'), (2, None, 'Web UI'))


class PathModes(Base):
    def test_every_unraid_mode_kept(self):
        for mode in ('rw', 'ro', 'rw,slave', 'ro,slave', 'rw,shared', 'ro,shared'):
            _, root = self.run_one(template(config('Media', '/media', '/mnt/user/media',
                                                   'Path', mode)))
            self.assertEqual(root.find('Config').get('Mode'), mode)

    def test_unknown_mode_falls_back_to_rw(self):
        _, root = self.run_one(template(config('Media', '/media', '/mnt', 'Path', 'bogus')))
        self.assertEqual(root.find('Config').get('Mode'), 'rw')


class Healthchecks(Base):
    def test_no_healthcheck_left_alone(self):
        body = config('Web', '80', '8080', 'Port', 'tcp')
        for repo in ('example/app', 'postgres:16', 'valkey/valkey', 'hotio/bazarr'):
            _, root = self.run_one(template(body, extra='--no-healthcheck', repo=repo,
                                            webui='http://[IP]:[PORT:80]/'))
            self.assertEqual(root.findtext('ExtraParams'), '--no-healthcheck', repo)

    def test_valkey_matched_on_repository_only(self):
        _, root = self.run_one(template('', name='App-Valkey', repo='redis:7'))
        self.assertNotIn('valkey-cli', root.findtext('ExtraParams') or '')
        _, root = self.run_one(template('', name='Cache', repo='valkey/valkey:8'))
        self.assertIn('valkey-cli', root.findtext('ExtraParams'))

    def test_servarr_matched_on_repository_only(self):
        body = config('Metrics', '9707', '9707', 'Port', 'tcp')
        _, root = self.run_one(template(body, name='Sonarr-Exporter',
                                        repo='ghcr.io/onedr0p/exportarr',
                                        webui='http://[IP]:[PORT:9707]/'))
        self.assertNotIn('/ping', root.findtext('ExtraParams'))
        body = config('Web', '8989', '8989', 'Port', 'tcp')
        _, root = self.run_one(template(body, name='TV', repo='ghcr.io/hotio/sonarr',
                                        webui='http://[IP]:[PORT:8989]/'))
        self.assertIn('/ping', root.findtext('ExtraParams'))


class NestedElements(Base):
    def test_nested_block_kept_verbatim(self):
        nested = ('  <Networking>\n    <Mode>bridge</Mode>\n    <Publish>\n'
                  '      <Port><HostPort>8080</HostPort></Port>\n    </Publish>\n'
                  '  </Networking>\n')
        _, root = self.run_one(template(nested))
        self.assertEqual(root.findtext('Networking/Mode'), 'bridge')
        self.assertEqual(root.findtext('Networking/Publish/Port/HostPort'), '8080')


class Idempotent(Base):
    def test_rerun_on_output_is_a_no_op(self):
        body = (config('Port 1: Web', '80', '8080', 'Port', 'tcp', 'Web UI.')
                + config('Path 01.0: Media', '/media', '/mnt/user/media', 'Path', 'ro,slave')
                + config('Path 01.1: Films', '/films', '/mnt/user/films', 'Path', 'rw')
                + config('DB_PASSWORD', 'DB_PASSWORD', 'hunter2', default='hunter2')
                + config('TZ', 'TZ', 'Europe/London')
                + '  <Networking>\n    <Mode>bridge</Mode>\n  </Networking>\n')
        xml = template(body, repo='ghcr.io/hotio/sonarr', webui='http://[IP]:[PORT:80]/')
        first, _ = self.run_one(xml)
        second, _ = self.run_one(first)
        self.assertEqual(first, second)


if __name__ == '__main__':
    unittest.main()
