import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verify_image import image_identity


class ImageIdentity(unittest.TestCase):
    def test_digest_architecture_and_entrypoint_are_actual_inspected_properties(self):
        digest = 'sha256:'+'a'*64
        image = 'registry.example.test/backup@'+digest
        item = {'Os': 'linux', 'Architecture': 'amd64', 'Id': 'sha256:'+'b'*64, 'RepoDigests': [image],
                'RootFS': {'Layers': ['sha256:'+'c'*64]},
                'Config': {'User': '0:0', 'Entrypoint': ['/usr/local/bin/python3', '/app/backup.py']}}
        self.assertEqual(image_identity(image, [item]), item['Id'])
        self.assertEqual(image_identity(item['Id'], [item]), item['Id'])
        for field, value in [('Architecture', 'arm64'), ('RepoDigests', []), ('Os', 'darwin')]:
            wrong = {**item, field: value}
            with self.assertRaises(ValueError):
                image_identity(image, [wrong])
        wrong = copy.deepcopy(item)
        wrong['Config']['Entrypoint'] = ['sh']
        with self.assertRaises(ValueError):
            image_identity(image, [wrong])
        with self.assertRaises(ValueError):
            image_identity('registry.example.test/backup:latest', [item])
