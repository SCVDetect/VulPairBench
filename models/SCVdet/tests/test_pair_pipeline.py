"""CPU/stdlib-only infrastructure tests; no DGL or checkpoint required."""
import csv
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import run_pairvul as tool


class TestPairPipeline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.old_storage = tool.STORAGE
        self.old_workspace = tool.WORKSPACE
        tool.STORAGE = self.root / 'storage'
        tool.WORKSPACE = self.root / 'VulPairBench'
        self.addCleanup(setattr, tool, 'STORAGE', self.old_storage)
        self.addCleanup(setattr, tool, 'WORKSPACE', self.old_workspace)
        self.samples = self.root / 'samples.csv'
        self.rows = []
        for i in (1, 2):
            for vers, label in (('before', 1), ('after', 0)):
                code = f'int test{i}() {{ // {vers} comment\nreturn {label}; }}\n'
                self.rows.append(dict(sample_id=f'pid{i}__{vers}', pair_id=f'pid{i}',
                                      version=vers, label=label, processed_func=code,
                                      source_sha256=tool.digest(code), cve_id='CVE-test'))
        tool.write_csv(self.samples, self.rows, list(self.rows[0]))
        self.opts = SimpleNamespace(dataset_tag='pilot', run_id='trial', samples=self.samples, rebuild=False,
                                    joern=None, joern_timeout=5, strict=False)

    def test_preserves_before_after_content_and_ids(self):
        inputs = tool.normalize_samples(self.samples)
        self.assertEqual(len(inputs), 4)
        out = tool.prepare(self.opts, inputs)
        self.assertEqual(len(out), 4)
        self.assertNotEqual(out[0]['graph_id'], out[1]['graph_id'])
        self.assertEqual(Path(out[0]['source_file']).read_text(), self.rows[0]['processed_func'])
        self.assertIn('/before/', out[0]['source_file'])
        self.assertIn('/after/', out[1]['source_file'])
        self.assertEqual(len(tool.existing_manifest(self.opts)), 4)

    def test_limit_keeps_complete_pair(self):
        inputs = tool.normalize_samples(self.samples, 1)
        self.assertEqual([r['version'] for r in inputs], ['before', 'after'])

    def test_rejects_incomplete_pair(self):
        tool.write_csv(self.samples, self.rows[:-1], list(self.rows[0]))
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            tool.normalize_samples(self.samples)

    def test_rejects_duplicate_version(self):
        tool.write_csv(self.samples, self.rows + [dict(self.rows[0], sample_id='another-id')], list(self.rows[0]))
        with self.assertRaisesRegex(ValueError, 'Duplicate before'):
            tool.normalize_samples(self.samples)

    def test_rejects_wrong_label(self):
        rows = [dict(r) for r in self.rows]
        rows[0]['label'] = 0
        tool.write_csv(self.samples, rows, list(rows[0]))
        with self.assertRaisesRegex(ValueError, 'Unexpected label'):
            tool.normalize_samples(self.samples)

    def test_rejects_source_hash_mismatch(self):
        rows = [dict(r) for r in self.rows]
        rows[0]['source_sha256'] = 'bad'
        tool.write_csv(self.samples, rows, list(rows[0]))
        with self.assertRaisesRegex(ValueError, 'Code SHA'):
            tool.normalize_samples(self.samples)

    def test_partial_pairs_excluded_and_reported(self):
        inputs = tool.normalize_samples(self.samples)
        preds = [dict(sample_id=x['sample_id'], pred_label=(1 if x['version']=='before' else 0),
                      score_vulnerable=(.9 if x['version']=='before' else .1)) for x in inputs[:3]]
        metrics = tool.paired_metrics(inputs, preds)
        self.assertEqual(metrics['total_pairs'], 2)
        self.assertEqual(metrics['evaluable_pairs'], 1)
        self.assertEqual(metrics['outcomes']['correct_pair'], 1)
        self.assertEqual(metrics['sample_coverage'], .75)
        self.assertEqual(metrics['pair_coverage'], .5)

    def test_joern_extracts_both_versions_and_resumes(self):
        # Controlled fake executable exercises the subprocess contract without Joern/DGL.
        executable = self.root / 'fake-joern'
        executable.write_text("""#!/usr/bin/env python3
import json, pathlib, sys
path = pathlib.Path(sys.argv[sys.argv.index('--param')+1].split('=',1)[1])
pathlib.Path(str(path) + '.nodes.json').write_text(json.dumps([{'id':1, '_label':'METHOD', 'lineNumber':1}]))
pathlib.Path(str(path) + '.edges.json').write_text(json.dumps([[1,1,'CFG','']]))
""")
        executable.chmod(0o755)
        tool.STORAGE.joinpath('external').mkdir(parents=True)
        tool.STORAGE.joinpath('external/get_func_graph.scala').write_text('// stub')
        self.opts.joern = executable
        records = tool.prepare(self.opts, tool.normalize_samples(self.samples))
        results = tool.extract(self.opts, records)
        self.assertEqual([r['status'] for r in results], ['ok'] * 4)
        cached = tool.extract(self.opts, records)
        self.assertEqual([r['status'] for r in cached], ['cached'] * 4)
        self.assertEqual(len(tool.read_csv(tool.WORKSPACE / 'Results/SCVdet/trial/joern_status.csv')), 4)

    def test_manifest_changes_require_rebuild(self):
        inputs = tool.normalize_samples(self.samples)
        tool.prepare(self.opts, inputs)
        with self.assertRaisesRegex(RuntimeError, 'different manifest'):
            tool.prepare(self.opts, inputs[:2])


if __name__ == '__main__':
    unittest.main()
