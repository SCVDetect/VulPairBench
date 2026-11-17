#!/usr/bin/env python3
"""Create the original StagedVulBERT function-level CSV contract from VulPairBench samples.csv.

Requires previously prepared samples.csv from VulPairBench/scripts/prepare_pairvul.py.
Does not normalize, drop, relabel, or modify source code. Cannot create line-level truth.
"""
import argparse
import csv
import json
from pathlib import Path

FIELDS = ['sample_id','pair_id','cve_id','cwe','version','source_sha256',
          'func_before','target','flaw_line_index']


def prepare(src, dst):
    src = Path(src)
    dst = Path(dst)
    with src.open('r', encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        if not {'sample_id','pair_id','cve_id','version','processed_func','target'}.issubset(reader.fieldnames or []):
            raise ValueError('Input must be the VulPairBench prepared samples.csv manifest')
        rows = list(reader)
    if not rows: raise ValueError('Empty input manifest')
    if len({r['sample_id'] for r in rows}) != len(rows): raise ValueError('Duplicate sample_id')
    for r in rows:
        if r['target'] not in {'0','1'} or r['version'] not in {'before','after'}:
            raise ValueError('Unrecognized target/version in '+r['sample_id'])
        if not r['processed_func'].strip():
            raise ValueError('Empty function in '+r['sample_id'])
    dst.parent.mkdir(parents=True,exist_ok=True)
    with dst.open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=FIELDS,extrasaction='ignore')
        writer.writeheader()
        for r in rows:
            # flaw_line_index is not provided by PairVul and not used by the FUNCTION model.
            # Do not fabricate vulnerability-line ground truth for line-level evaluation.
            writer.writerow({**r, 'func_before':r['processed_func'], 'flaw_line_index':''})
    return {'samples':len(rows),'pairs':len({r['pair_id'] for r in rows}),
            'before':sum(r['version']=='before' for r in rows),
            'after':sum(r['version']=='after' for r in rows),
            'output':str(dst), 'note':'No cleaning or filtering applied; function-level only; line labels unavailable'}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--samples',required=True)
    ap.add_argument('--out',required=True)
    args=ap.parse_args()
    print(json.dumps(prepare(args.samples,args.out),indent=2))

if __name__=='__main__':main()
