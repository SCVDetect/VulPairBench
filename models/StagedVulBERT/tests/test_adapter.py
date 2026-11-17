import csv
from pathlib import Path
import tempfile
import unittest
import importlib.util

SOURCE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('adapter',SOURCE/'scripts/prepare_input.py')
adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(adapter)

class TestAdapter(unittest.TestCase):
    def test_preserves_pairs_and_code(self):
        with tempfile.TemporaryDirectory() as d:
            src=Path(d)/'samples.csv';dst=Path(d)/'staged.csv'
            rows=[]
            for ver,lbl,code in [('before',1,'int f(){/* a */return 1;}'),('after',0,'int f(){return 0;}')]:
                rows.append({'sample_id':ver,'pair_id':'p','cve_id':'CVE-1','version':ver,
                             'target':str(lbl),'processed_func':code,'source_sha256':'abc'})
            with src.open('w',newline='') as f:
                writer=csv.DictWriter(f,fieldnames=rows[0].keys());writer.writeheader();writer.writerows(rows)
            stats=adapter.prepare(src,dst)
            self.assertEqual(stats['samples'],2)
            with dst.open(newline='') as f:out=list(csv.DictReader(f))
            self.assertEqual([r['func_before'] for r in out],[r['processed_func'] for r in rows])
            self.assertEqual([r['target'] for r in out],['1','0'])
            self.assertTrue(all(r['flaw_line_index']=='' for r in out))
    def test_rejects_duplicates(self):
        with tempfile.TemporaryDirectory() as d:
            src=Path(d)/'samples.csv'
            src.write_text('sample_id,pair_id,cve_id,version,processed_func,target\na,p,CVE-1,before,int a(){return 1;},1\na,p,CVE-1,after,int b(){return 0;},0\n')
            with self.assertRaises(ValueError):adapter.prepare(src,Path(d)/'out.csv')

if __name__=='__main__':unittest.main()
