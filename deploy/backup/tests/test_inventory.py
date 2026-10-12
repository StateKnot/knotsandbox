import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import inventory


def objects():
    values = {'config': b'encrypted configuration'}
    snapshot = hashlib.sha256(b'encrypted snapshot').hexdigest()
    for group, raw in [('keys', b'key metadata'), ('index', b'encrypted index'), ('data', b'encrypted pack'), ('snapshots', b'encrypted snapshot')]:
        key = hashlib.sha256(raw).hexdigest()
        values[group + '/' + (key[:2] + '/' if group == 'data' else '') + key] = raw
    return values, snapshot


class Inventory(unittest.TestCase):
    def build(self, values, snapshot, listing=None, patch_object=None):
        c = {k: '00000000-0000-4000-8000-00000000000' + str(i) for i, k in enumerate(['tenant_id', 'backup_id', 'seal_attempt_id', 'cluster_epoch'], 1)}
        def run(command, deadline, env, sink):
            if command[1] == 'lsf':
                data = listing or ''.join(f'{len(value)}\t{key}\n' for key, value in reversed(list(values.items()))).encode()
            elif command[1] == 'hashsum':
                self.assertIn('--download', command)
                data = ''.join(hashlib.sha256(raw).hexdigest() + '  ' + key + '\n' for key, raw in (values if patch_object is None else patch_object).items()).encode()
            else:
                raise AssertionError(command)
            for offset in range(0, len(data), 7):
                sink(data[offset:offset+7])
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / 'inventory'
            result = inventory.build(c, snapshot, 'remote', folder, 1e15, {}, run)
            inventory.validate(result)
            chunks = [json.loads((folder / Path(s['key']).name).read_bytes()) for s in result['shards']]
            for descriptor in result['shards']:
                body = (folder / Path(descriptor['key']).name).read_bytes()
                self.assertEqual(hashlib.sha256(body).hexdigest(), descriptor['sha256'])
                self.assertEqual(body, inventory.canonical(json.loads(body)))
            self.assertFalse((folder / 'index.sqlite').exists())
            return result, chunks
    def test_real_hashes_sorted_shards_bound_identity_and_counts(self):
        values, snapshot = objects()
        with patch('inventory.MAX_SHARD_BYTES', 700):
            result, chunks = self.build(values, snapshot)
        self.assertGreater(len(result['shards']), 1)
        all_objects = [o for chunk in chunks for o in chunk['objects']]
        self.assertEqual([o['key'] for o in all_objects], sorted(values))
        self.assertEqual(result['total_bytes'], sum(map(len, values.values())))
        self.assertTrue(all('seal_attempt_id' in chunk and 'cluster_epoch' in chunk for chunk in chunks))
    def test_truncation_growth_same_size_corruption_fail(self):
        values, snapshot = objects()
        key = next(k for k in values if k.startswith('data/'))
        for body in [values[key][:-1], values[key] + b'x', b'x' * len(values[key])]:
            with self.assertRaises(ValueError):
                self.build(values, snapshot, patch_object=values | {key: body})
    def test_missing_pack_other_snapshot_lock_or_path_traversal_fail(self):
        values, snapshot = objects()
        for bad in ['locks/' + 'a' * 64, '../outside', 'snapshots/' + 'b' * 64, 'data/00/' + '1' * 64]:
            with self.assertRaises(ValueError):
                self.build(values | {bad:b'x'}, snapshot)
        with self.assertRaisesRegex(ValueError, 'INCOMPLETE'):
            self.build({k:v for k,v in values.items() if not k.startswith('data/')}, snapshot)
    def test_duplicate_list_entry_and_frame_overflow_fail(self):
        values, snapshot = objects()
        with self.assertRaises(inventory.sqlite3.IntegrityError):
            self.build(values, snapshot, listing=b'1\tconfig\n1\tconfig\n')
        with self.assertRaisesRegex(ValueError, 'FRAME'):
            self.build(values, snapshot, listing=b'a' * 257)
    def test_missing_hash_or_unlisted_object_never_seals(self):
        values, snapshot = objects()
        removed = {k:v for k,v in values.items() if not k.startswith('data/')}
        for hashes in [removed, {}]:
            with self.assertRaisesRegex(ValueError, 'HASH_INCOMPLETE'):
                self.build(values, snapshot, patch_object=hashes)
        extra = dict(values)
        raw = b'additional unlisted pack'
        digest = hashlib.sha256(raw).hexdigest()
        extra['data/' + digest[:2] + '/' + digest] = raw
        with self.assertRaisesRegex(ValueError, 'SET_CHANGED'):
            self.build(values, snapshot, patch_object=extra)
    def test_fixed_limits_and_descriptor_paths_fail_closed(self):
        values, snapshot = objects()
        with patch('inventory.MAX_OBJECTS', 4), self.assertRaisesRegex(ValueError, 'LIMIT'):
            self.build(values, snapshot)
        result, _ = self.build(values, snapshot)
        result['shards'][0]['key'] = '../outside'
        with self.assertRaisesRegex(ValueError, 'KEY'):
            inventory.validate(result)


if __name__ == '__main__':
    unittest.main()
