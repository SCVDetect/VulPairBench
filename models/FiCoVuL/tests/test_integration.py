import csv
import importlib.util
import json
import pathlib
import sys
import tempfile
import types
import unittest
from types import SimpleNamespace

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'scripts' / 'run_pairvul.py'
spec = importlib.util.spec_from_file_location('ficovul_adapter', SCRIPT)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def records():
    return [
        {'sample_id':'p001__before','pair_id':'p001','version':'before','target':'1','processed_func':'int vulnerable(){return 1;}\n'},
        {'sample_id':'p001__after','pair_id':'p001','version':'after','target':'0','processed_func':'int vulnerable(){return 0;}\n'},
        {'sample_id':'p002__before','pair_id':'p002','version':'before','target':'1','processed_func':'int second(){return 2;}\n'},
        {'sample_id':'p002__after','pair_id':'p002','version':'after','target':'0','processed_func':'int second(){return 0;}\n'},
    ]


class AdapterTests(unittest.TestCase):
    def test_valid_pairs(self):
        groups=a.normalize_samples(records())
        self.assertEqual(len(groups),2)
        self.assertEqual(groups['p001']['before']['label'],1)
        self.assertEqual(groups['p001']['after']['label'],0)
    def test_missing_version_rejected(self):
        with self.assertRaisesRegex(ValueError,'Incomplete pairs'):
            a.normalize_samples(records()[:-1])
    def test_wrong_label_rejected(self):
        r=records();r[0]['target']='0'
        with self.assertRaisesRegex(ValueError,'mismatch'):
            a.normalize_samples(r)
    def test_duplicate_sample_rejected(self):
        r=records();r[1]['sample_id']=r[0]['sample_id']
        with self.assertRaisesRegex(ValueError,'Duplicate sample_id'):
            a.normalize_samples(r)
    def test_unsafe_filename_hashed(self):
        self.assertEqual(a.normalized_graph_id('p01__before'),'p01__before')
        self.assertRegex(a.normalized_graph_id('../bad'),r'^s[a-f0-9]{24}$')
    def test_tag_traversal_rejected(self):
        with self.assertRaises(ValueError):a.work_dir('../../outside')
        with self.assertRaises(ValueError):a.result_dir('bad/path')
    def test_prepare_pilot_and_verbatim_code(self):
        with tempfile.TemporaryDirectory() as td:
            src=pathlib.Path(td);input=src/'samples.csv'
            a.atomic_csv(input,records(),list(records()[0]))
            model=a.MODEL
            try:
                a.MODEL=src/'models'/'FiCoVuL'
                opts=SimpleNamespace(samples=str(input),dataset_tag='pilot',limit_pairs=1,overwrite=False)
                a.stage_prepare(opts)
                manifest=a.read_csv(a.work_dir('pilot')/'manifest.csv')
                self.assertEqual(len(manifest),2)
                for r in manifest:
                    source=(a.work_dir('pilot')/r['source_file']).read_text()
                    self.assertEqual(a.sha(source.encode()),r['code_sha256'])
                    self.assertIn(r['version'],r['source_file'])
                self.assertFalse((src/'models'/'FiCoVuL'/'checkpoints').exists())
            finally:a.MODEL=model
    def test_existing_modified_source_never_overwritten_silently(self):
        with tempfile.TemporaryDirectory() as td:
            src=pathlib.Path(td);input=src/'samples.csv'
            a.atomic_csv(input,records(),list(records()[0]))
            model=a.MODEL
            try:
                a.MODEL=src
                opts=SimpleNamespace(samples=str(input),dataset_tag='pilot',limit_pairs=1,overwrite=False)
                a.stage_prepare(opts)
                source=a.work_dir('pilot')/'source'/'before'/'p001__before.c'
                source.write_text('changed!')
                with self.assertRaises(FileExistsError):a.stage_prepare(opts)
            finally:a.MODEL=model
    def test_no_graph_prediction_without_checkpoint(self):
        with tempfile.TemporaryDirectory() as td:
            opts=SimpleNamespace(checkpoint=str(pathlib.Path(td)/'missing.pth'),run_id='testing',dataset_tag='test',overwrite=False)
            with self.assertRaises(FileNotFoundError):
                a.stage_predict(opts)
    def test_feature_schema_controlled_without_original_deps(self):
        mod=types.ModuleType('FiCoVuL.dataset.data_preprocess')
        class Stub:
            def __init__(self,*args,**kwargs):self.renamer={}
            def localize_tokens(self, start,end):return ['Token.Name'],['v']
        mod.CodeNormalizer=Stub
        hold={k:sys.modules.get(k) for k in ('FiCoVuL','FiCoVuL.dataset','FiCoVuL.dataset.data_preprocess')}
        for name in hold:
            if name not in sys.modules:sys.modules[name]=types.ModuleType(name)
        sys.modules['FiCoVuL.dataset.data_preprocess']=mod
        try:
            g={'nodes':{'0':{'type':'METHOD','code':'f','line':-1,'column':-1},'1':{'type':'METHOD_RETURN','code':'RET','line':-1,'column':-1}},
               'edges':[[0,1,0]]}
            maps=(['METHOD','METHOD_RETURN'],['Token.Name.Function','Token.Keyword','<UNK>'],['f','RET','<UNK>'],[])
            native=a.make_native_graph(g,'int f(){return 1;}',1,maps,'RAW')
            self.assertEqual(native['node_types'],[0,1])
            self.assertEqual(native['edges'],[[0,1,0]])
            self.assertEqual(native['rpst_nodes'],{'0':[],'1':[]})
            g['nodes']['1']['type']='UNKNOWN'
            with self.assertRaises(ValueError):a.make_native_graph(g,'int f(){return 1;}',1,maps,'RAW')
        finally:
            for name,val in hold.items():
                if val is None:sys.modules.pop(name,None)
                else:sys.modules[name]=val

if __name__ == '__main__':unittest.main()
