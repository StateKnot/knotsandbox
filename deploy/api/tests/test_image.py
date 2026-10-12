import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('api_init_image', ROOT / 'check_image.py')
image = importlib.util.module_from_spec(spec); spec.loader.exec_module(image)


class CandidateFixtureBoundaries(unittest.TestCase):
    def test_cleanup_checks_exact_random_fixture_and_never_forces_removal(self):
        name = 'sandbox-api-init-' + 'a' * 32 + '-public'
        for running in (False, True):
            calls = []
            def command(arguments):
                calls.append(arguments)
                return SimpleNamespace(stdout=json.dumps([{'Name':'/' + name,
                    'State':{'Running':running}}]).encode())
            image.remove_fixture_container(command, name)
            self.assertEqual(calls[0], ['inspect', name])
            self.assertEqual(calls[-1], ['rm', name])
            self.assertEqual(len(calls), 3 if running else 2)
            self.assertFalse(any('--force' in call for call in calls))
            if running: self.assertEqual(calls[1], ['stop', '--time', '3', name])
        calls = []
        def different(arguments):
            calls.append(arguments)
            return SimpleNamespace(stdout=json.dumps([{'Name':'/unrelated',
                'State':{'Running':True}}]).encode())
        with self.assertRaises(ValueError): image.remove_fixture_container(different, name)
        self.assertEqual(calls, [['inspect', name]])
        with self.assertRaises(ValueError): image.remove_fixture_container(different, 'unrelated')
        self.assertEqual(calls, [['inspect', name]])

    def test_source_archive_fixed_metadata_without_helper_container(self):
        data = image.archive({'cursor/keyring.json': b'public'}, 0o550)
        with tarfile.open(fileobj=io.BytesIO(data)) as bundle:
            self.assertEqual({member.name for member in bundle}, {'.', 'cursor', 'cursor/keyring.json'})
            for member in bundle:
                self.assertEqual((member.uid, member.gid), (0, 10001))
                self.assertEqual(member.mode, 0o550 if member.isdir() else 0o440)
        with tarfile.open(fileobj=io.BytesIO(image.archive({}, 0o770, root='api-private'))) as bundle:
            member = bundle.getmembers()[0]
            self.assertEqual((member.name, member.uid, member.gid, member.mode), ('api-private', 0, 10001, 0o770))

    def test_output_inspection_rejects_modes_owner_links_extra_and_changed_content(self):
        def bundle(mode=0o600, uid=10001, content=b'public', extra=False, link=False):
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode='w') as output:
                directory = tarfile.TarInfo('private'); directory.type = tarfile.DIRTYPE
                directory.uid = 10001; directory.gid = 10001; directory.mode = 0o700; output.addfile(directory)
                member = tarfile.TarInfo('private/cursor.json'); member.uid = uid; member.gid = 10001; member.mode = mode
                if link:
                    member.type = tarfile.SYMTYPE; member.linkname = '/etc/shadow'; output.addfile(member)
                else:
                    member.size = len(content); output.addfile(member, io.BytesIO(content))
                if extra:
                    other = tarfile.TarInfo('private/extra'); other.uid = other.gid = 10001; other.mode = 0o600; output.addfile(other)
            return data.getvalue()
        image.inspect_bundle(bundle(), {'cursor.json': b'public'})
        for change in [{'mode':0o644}, {'uid':0}, {'content':b'changed'}, {'extra':True}, {'link':True}]:
            with self.assertRaises(ValueError): image.inspect_bundle(bundle(**change), {'cursor.json':b'public'})


if __name__ == '__main__': unittest.main()
