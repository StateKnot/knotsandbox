"""Counterexamples for the public node-image protocol fixture; no Docker."""
import json
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_pipeline import (NODE_FILESYSTEMS, NODE_QUERY_VALUES, NODE_SCALARS,
                            node_fixture_rows, node_image_query)
from test_observability import fixture


def samples(rows):
    parsed = []
    for row in rows:
        match = re.fullmatch(r'([a-z_]+)\{(.+)\} (-?[0-9]+) 1600000000000', row)
        if match is None:
            raise AssertionError('Fixture must preserve its deliberately old wire timestamp')
        labels = {key: json.loads(value) for key, value in
                  re.findall(r'([a-z_][a-z0-9_]*)=("(?:[^"\\]|\\.)*")', match[2])}
        parsed.append((match[1], labels, int(match[3])))
    return parsed


class NodeImagePipelineFixture(unittest.TestCase):
    def setUp(self):
        self.settings, _, _ = fixture()
        for i, node in enumerate(self.settings['nodes']):
            node['image_profile_sha256'] = format(i + 1, '064x')
        self.clock = 2000000000

    def good(self, replica, stale=False):
        return [(metric, labels, value) for metric, labels, value in
                samples(node_fixture_rows(self.settings, replica, self.clock, stale=stale))
                if value >= 0]

    def test_wire_fixture_keeps_the_actual_body_budget_and_adversarial_origins(self):
        for replica in ('a', 'b'):
            rows = node_fixture_rows(self.settings, replica, self.clock)
            self.assertLessEqual(len(('\n'.join(rows) + '\n').encode()), 64 * 1024)
            parsed = samples(rows)
            poisoned = [labels for _, labels, value in parsed if value == -424242]
            for key, value in [('source', 'KUBERNETES_API_READBACK'), ('completeness', 'COMPLETE'),
                               ('deployment', 'sandbox-other'), ('profile_sha256', 'f' * 64)]:
                self.assertTrue(any(labels[key] == value for labels in poisoned))
            self.assertTrue(any('filesystem_id' in labels and not re.fullmatch('[0-9a-f]{64}', labels['filesystem_id'])
                                for labels in poisoned))
            self.assertTrue(all(labels.get('secret_label') == 'MUST_BE_REMOVED' for _, labels, _ in parsed))

    def test_fresh_scrape_cannot_hide_stale_runtime_or_a_stale_ha_replica(self):
        first, second = (node['node_uid'] for node in self.settings['nodes'])
        def value(replica, node_uid, metric):
            values = [amount for name, labels, amount in self.good(replica, stale=True)
                      if labels['node_uid'] == node_uid and name == metric]
            self.assertEqual(len(values), 1)
            return values[0]
        for replica in ('a', 'b'):
            self.assertEqual(value(replica, first, NODE_SCALARS[2]), self.clock)
            self.assertEqual(value(replica, first, NODE_FILESYSTEMS[0]), self.clock - 120)
        self.assertEqual(value('a', second, NODE_SCALARS[2]), self.clock)
        self.assertEqual(value('b', second, NODE_SCALARS[2]), self.clock - 120)
        self.assertEqual(value('b', second, NODE_FILESYSTEMS[0]), self.clock - 5)
        self.assertEqual(value('a', second, NODE_FILESYSTEMS[1]), 8192)
        self.assertEqual(value('b', second, NODE_FILESYSTEMS[1]), 999999)

    def test_unknown_fixture_has_only_failed_observation_flags_and_no_zero_fill(self):
        for replica in ('a', 'b'):
            rows = samples(node_fixture_rows(self.settings, replica, self.clock, stale=True, unknown=True))
            self.assertEqual(len(rows), len(self.settings['nodes']) * 2)
            self.assertEqual({metric for metric, _, _ in rows}, set(NODE_SCALARS[:2]))
            self.assertTrue(all(value == 0 for _, _, value in rows))

    def test_fixture_query_accepts_only_fixed_quantities_and_explicit_opt_in(self):
        for metric in NODE_QUERY_VALUES:
            self.assertTrue(node_image_query(self.settings, metric).startswith('max without(collector_replica,job,instance) ('))
        for metric in ('sandbox_vm_memory_bytes', 'sandbox_node_image_capacity_bytes', 'x{} or vector(1)'):
            with self.assertRaisesRegex(ValueError, 'NODE_IMAGE_QUERY_FIXED_METRIC_REQUIRED'):
                node_image_query(self.settings, metric)
        for node in self.settings['nodes']:
            del node['image_profile_sha256']
        with self.assertRaisesRegex(ValueError, 'NODE_IMAGE_QUERY_OPT_IN_REQUIRED'):
            node_image_query(self.settings, NODE_SCALARS[3])


if __name__ == '__main__':
    unittest.main()
