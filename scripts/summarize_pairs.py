#!/usr/bin/env python3
"""Compute model coverage and independent before/after pair discrimination."""
import argparse
import csv
import json
from collections import defaultdict,Counter
from pathlib import Path


def analyze(path):
    with Path(path).open(newline='',encoding='utf-8') as f:rows=list(csv.DictReader(f))
    grouped=defaultdict(dict)
    for r in rows:
        if r['version'] not in ('before','after'):raise ValueError('Bad version')
        pair_id=r['pair_id'];version=r['version']
        if version in grouped[pair_id]:raise ValueError(f'Duplicate version for pair {pair_id}')
        grouped[pair_id][version]=r
    outcomes=Counter();details=[]
    for pair_id,d in grouped.items():
        if set(d)!= {'before','after'}:
            outcomes['missing_version']+=1;continue
        before=d['before'];after=d['after']
        if before['status']!='ok' or after['status']!='ok' or any(r['pred_label'] not in ('0','1') for r in d.values()):
            outcomes['unsupported_pair']+=1;continue
        if before['true_label']!='1' or after['true_label']!='0':
            raise ValueError(f'Unexpected expected labels for pair {pair_id}')
        bp=int(before['pred_label']);ap=int(after['pred_label'])
        category={ (1,0):'correct_pair',(1,1):'both_vulnerable',
                   (0,0):'both_benign',(0,1):'inverted'}[bp,ap]
        outcomes[category]+=1
        score_delta=''
        if before['score_vulnerable'] and after['score_vulnerable']:
            score_delta=float(before['score_vulnerable'])-float(after['score_vulnerable'])
        details.append({'pair_id':pair_id,'cve_id':before['cve_id'],'outcome':category,
                        'before_pred':bp,'after_pred':ap,'score_delta':score_delta})
    evaluable=sum(outcomes[k] for k in ('correct_pair','both_vulnerable','both_benign','inverted'))
    return {'source':str(path),'total_pairs':len(grouped),'evaluable_pairs':evaluable,
            'pair_coverage':round(evaluable/len(grouped),6) if grouped else None,
            'pair_accuracy':round(outcomes['correct_pair']/evaluable,6) if evaluable else None,
            'label_change_rate':round((outcomes['correct_pair']+outcomes['inverted'])/evaluable,6) if evaluable else None,
            'outcomes':dict(outcomes)},details


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--predictions',type=Path,required=True)
    ap.add_argument('--out-dir',type=Path,required=True)
    args=ap.parse_args()
    result,details=analyze(args.predictions)
    args.out_dir.mkdir(exist_ok=True,parents=True)
    (args.out_dir/'summary.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    with (args.out_dir/'pair_outcomes.csv').open('w',newline='',encoding='utf-8') as h:
        writer=csv.DictWriter(h,fieldnames=['pair_id','cve_id','outcome','before_pred','after_pred','score_delta']);writer.writeheader();writer.writerows(details)
    print(json.dumps(result,indent=2))

if __name__=='__main__': main()
