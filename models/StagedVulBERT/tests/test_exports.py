import csv
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
import numpy as np
import pandas as pd

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('vulpair_utils',ROOT/'Entry/vulpair_utils.py')
utils=importlib.util.module_from_spec(spec);spec.loader.exec_module(utils)

class FakeFeature:
    def __init__(self, n):self.row_idx=list(range(n+1))
class FakeExample:
    def __init__(self, n, visible):
        self.input_tokens=['<s>']+list(range(n))+['</s>']
        self.tokens_features=[FakeFeature(visible),None,None,None]
class TestExports(unittest.TestCase):
    def test_probability_and_alignment(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); inp=p/'test.csv'; result=p/'Results'
            pd.DataFrame([dict(sample_id='p0__before',pair_id='p0',cve_id='CVE-1',version='before',
                               target=1,func_before='return 1;',source_sha256='hash1'),
                          dict(sample_id='p0__after',pair_id='p0',cve_id='CVE-1',version='after',
                               target=0,func_before='return 0;',source_sha256='hash2')]).to_csv(inp,index=False)
            ds=types.SimpleNamespace(examples=[FakeExample(8,8),FakeExample(9,4)])
            args=types.SimpleNamespace(results_dir=str(result),test_data_file=str(inp),run_id='run1')
            logits=np.asarray([[0.1,0.9],[0.8,0.2]])
            utils.write_evaluation(args,ds,logits,np.asarray([1,0]),0.5,{'eval_f1':1.0,'eval_IoU':float('nan')})
            with (result/'predictions.csv').open(newline='') as f:
                preds=list(csv.DictReader(f))
            self.assertEqual([p['sample_id'] for p in preds],['p0__before','p0__after'])
            self.assertEqual([p['pred_label'] for p in preds],['1','0'])
            self.assertAlmostEqual(float(preds[0]['score_vulnerable']),.9)
            with (result/'raw_preds.csv').open(newline='') as f:
                raw=list(csv.DictReader(f))
            self.assertEqual([p['truncated'] for p in raw],['False','True'])
            self.assertEqual([p['visible_tokens'] for p in raw],['8','4'])
            self.assertTrue((result/'metrics.json').is_file())
    def test_label_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            inp=Path(d)/'test.csv'
            pd.DataFrame([dict(sample_id='p0__before',pair_id='p0',cve_id='CVE-1',version='before',target=1)]).to_csv(inp,index=False)
            with self.assertRaisesRegex(RuntimeError,'labels'):
                utils.write_evaluation(types.SimpleNamespace(results_dir=str(Path(d)/'R'),test_data_file=str(inp),run_id='r'),
                    types.SimpleNamespace(examples=[FakeExample(1,1)]),np.array([[0.9,0.1]]),np.array([0]),0.5,{})

if __name__=='__main__':unittest.main()
