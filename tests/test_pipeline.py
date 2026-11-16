"""CPU-only tests. Run: python -m unittest discover -s tests -v"""
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from prepare_pairvul import prepare
from standardize_predictions import standardize
from summarize_pairs import analyze


class PairTools(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)
        data=[{'cve_id':'CVE-1','id':42,'cwe':['CWE-20'],
               'code_before_change':'int a(){return 1;}','code_after_change':'int a(){return 2;}'},
              {'cve_id':'CVE-2','id':77,'cwe':['CWE-119'],
               'code_before_change':'int b(){ return 1; }','code_after_change':'int b(){ return 1; }'}]
        (self.path/'pairs.json').write_text(json.dumps(data),encoding='utf-8')
    def tearDown(self):self.tmp.cleanup()
    def test_pipeline_and_pair_accuracy(self):
        report=prepare(self.path/'pairs.json',self.path/'processed',export_c=True)
        self.assertEqual(report['source_pairs'],2)
        self.assertEqual(report['samples'],4)
        self.assertEqual(report['flag_counts']['identical_code'],1)
        with (self.path/'processed/samples.csv').open() as fh:
            manifest=list(csv.DictReader(fh))
        self.assertEqual(len(list((self.path/'processed/c_files').glob('*.c'))),4)
        self.assertEqual([r['label'] for r in manifest],['1','0','1','0'])
        inp=self.path/'raw.csv'
        # deliberately reverse prediction rows: adapter MUST join by sample_id
        with inp.open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=['sample_id','pred_label','score_vulnerable']);w.writeheader()
            for item in reversed(manifest):
                w.writerow({'sample_id':item['sample_id'],'pred_label':item['label'],
                            'score_vulnerable': '0.8' if item['label']=='1' else '0.2'})
        output=self.path/'predictions.csv'
        count,ok=standardize(self.path/'processed/samples.csv',inp,output,'LineVul','test')
        self.assertEqual((count,ok),(4,4))
        result,details=analyze(output)
        self.assertEqual(result['evaluable_pairs'],2)
        self.assertEqual(result['pair_accuracy'],1.0)
        self.assertEqual(result['label_change_rate'],1.0)
        self.assertEqual(len(details),2)
    def test_missing_predictions_count_as_coverage_failure(self):
        prepare(self.path/'pairs.json',self.path/'processed')
        with (self.path/'processed/samples.csv').open() as fh:
            manifest=list(csv.DictReader(fh))
        inp=self.path/'raw.csv'
        with inp.open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=['sample_id','pred_label']);w.writeheader()
            w.writerow({'sample_id':manifest[0]['sample_id'],'pred_label':1})
        output=self.path/'predictions.csv'
        standardize(self.path/'processed/samples.csv',inp,output,'SCVdet','pilot')
        result,_=analyze(output)
        self.assertEqual(result['evaluable_pairs'],0)
        self.assertEqual(result['total_pairs'],2)
    def test_mapping_rejects_wrong_sample_ids(self):
        prepare(self.path/'pairs.json',self.path/'processed')
        inp=self.path/'raw.csv';out=self.path/'predictions.csv'
        with inp.open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=['function_id','func_level_pred']);w.writeheader();w.writerow({'function_id':99,'func_level_pred':1})
        with self.assertRaises(ValueError):
            standardize(self.path/'processed/samples.csv',inp,out,'SCVdet','pilot',id_col='function_id',pred_col='func_level_pred')
    def test_mapping_resolves_graph_ids(self):
        prepare(self.path/'pairs.json',self.path/'processed')
        with (self.path/'processed/samples.csv').open() as fh:
            manifest=list(csv.DictReader(fh))
        prediction=self.path/'raw.csv'
        with prediction.open('w',newline='') as fh:
            wr=csv.DictWriter(fh,fieldnames=['function_id','func_level_pred','score_vulnerable'])
            wr.writeheader()
            for idx, item in enumerate(manifest):
                wr.writerow({'function_id':idx,'func_level_pred':item['label'],
                             'score_vulnerable':0.9 if item['label']=='1' else 0.1})
        mapping=self.path/'mapping.csv'
        with mapping.open('w',newline='') as fh:
            wr=csv.DictWriter(fh,fieldnames=['model_sample_id','sample_id']);wr.writeheader()
            for idx,item in enumerate(manifest):wr.writerow({'model_sample_id':idx,'sample_id':item['sample_id']})
        output=self.path/'std.csv'
        count,ok=standardize(self.path/'processed/samples.csv',prediction,output,'SCVdet','test',
                             id_col='function_id',pred_col='func_level_pred',mapping_path=mapping)
        self.assertEqual((count,ok),(4,4))
        self.assertEqual(analyze(output)[0]['pair_accuracy'],1.0)

    def test_model_output_paths(self):
        # AST extraction means no torch/dgl/sklearn required for this test.
        import ast,os,re
        for model,path in [
           ('SCVdet',ROOT/'models/SCVdet/sourcescripts/uutils/__utils__.py'),
           ('VVulDet',ROOT/'models/VVulDet/sourcescripts/utils/utills.py')]:
            source=path.read_text()
            tree=ast.parse(source)
            funcs=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('outputs_dir','checkpoints_dir')]
            namespace={'Path':Path,'os':os,'re':re,'__file__':str(path)}
            exec(compile(ast.Module(body=funcs,type_ignores=[]),str(path),'exec'),namespace)
            from unittest.mock import patch
            with patch.dict(os.environ,{'VULPAIR_RUN_ID':'testing-paths'}):
                self.assertEqual(namespace['outputs_dir'](),ROOT/'Results'/model/'testing-paths')
            self.assertEqual(namespace['checkpoints_dir'](),ROOT/'models'/model/'checkpoints')

    def test_runner_dry_run(self):
        cmd=[sys.executable,str(ROOT/'scripts/run_model.py'),'--model','VVulDet','--run-id','dry-run-check','--dry-run']
        p=subprocess.run(cmd,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('DRY RUN ONLY',p.stdout)

if __name__=='__main__':unittest.main()
