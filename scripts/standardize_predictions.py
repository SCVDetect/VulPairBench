#!/usr/bin/env python3
"""Join model predictions to a test manifest by sample ID (never by row number)."""
import argparse
import csv
import math
import re
from pathlib import Path

MODELS={'LineVul','SCVdet','VVulDet'}
FIELDS=['model','run_id','sample_id','pair_id','cve_id','version','true_label',
        'pred_label','score_vulnerable','status','source_sha256']


def read_rows(path):
    with Path(path).open(newline='',encoding='utf-8-sig') as f:
        reader=csv.DictReader(f)
        if reader.fieldnames is None: raise ValueError(f'Empty CSV: {path}')
        return list(reader),reader.fieldnames


def safe_run(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',value) or value in ('.','..'):
        raise ValueError('Invalid run ID')
    return value


def standardize(manifest_path, raw_path, dest, model, run_id,
                id_col='sample_id', pred_col='pred_label', score_col='score_vulnerable',status_col=None,
                threshold=0.5, mapping_path=None):
    if model not in MODELS:raise ValueError('Unknown model: '+model)
    safe_run(run_id)
    manifest, mcols=read_rows(manifest_path)
    raw, rcols=read_rows(raw_path)
    for required in ('sample_id','pair_id','cve_id','version','label'):
        if required not in mcols:raise ValueError('Missing manifest column: '+required)
    if id_col not in rcols:raise ValueError('No matching input identifier column: '+id_col)
    if status_col and status_col not in rcols:raise ValueError('No status column: '+status_col)
    if pred_col not in rcols and score_col not in rcols:
        raise ValueError(f'Raw prediction CSV needs {pred_col!r} or {score_col!r}')
    unique={}
    for row in raw:
        sid=row[id_col]
        if sid in unique:raise ValueError('Duplicate prediction sample_id: '+sid)
        unique[sid]=row
    if mapping_path is not None:
        mapping, mapping_columns = read_rows(mapping_path)
        if 'model_sample_id' not in mapping_columns or 'sample_id' not in mapping_columns:
            raise ValueError('Mapping needs model_sample_id and sample_id columns')
        idmap={}
        for record in mapping:
            modelid=record['model_sample_id']
            if modelid in idmap: raise ValueError('Duplicate model_sample_id in mapping: '+modelid)
            idmap[modelid]=record['sample_id']
        if set(unique)-set(idmap): raise ValueError('Missing model identifiers in mapping')
        mapped={}
        for modelid, sample in unique.items():
            sid=idmap[modelid]
            if sid in mapped:raise ValueError('Two model IDs map to the same sample_id: '+sid)
            mapped[sid]=sample
        unique=mapped
    manifest_ids={r['sample_id'] for r in manifest}
    if len(manifest_ids)!=len(manifest): raise ValueError('Duplicate IDs in manifest')
    extras=set(unique)-manifest_ids
    if extras:raise ValueError(f'{len(extras)} predictions with IDs absent from manifest (e.g. {next(iter(extras))})')
    out=[]
    for record in manifest:
        sid=record['sample_id'];rawrec=unique.get(sid)
        status='missing' if rawrec is None else (rawrec.get(status_col,'ok') if status_col else 'ok')
        status=status or 'failed'
        label='';score=''
        if rawrec is not None and status=='ok':
            if score_col in rcols and rawrec.get(score_col,'') not in ('',None):
                x=float(rawrec[score_col])
                if not math.isfinite(x) or x<0 or x>1:raise ValueError('score_vulnerable must be finite probability in [0,1]')
                score=str(x)
            if pred_col in rcols and rawrec.get(pred_col,'') not in ('',None):
                predicted=float(rawrec[pred_col])
                if not math.isfinite(predicted) or predicted not in (0.0, 1.0):
                    raise ValueError('pred_label must be exactly 0 or 1')
                label=str(int(predicted))
            elif score:label=str(int(float(score)>=threshold))
            else:status='no_prediction'
        out.append({'model':model,'run_id':run_id,'sample_id':sid,'pair_id':record['pair_id'],
                    'cve_id':record['cve_id'],'version':record['version'],
                    'true_label':record['label'],'pred_label':label,'score_vulnerable':score,
                    'status':status,'source_sha256':record.get('source_sha256','')})
    dest=Path(dest);dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=FIELDS);writer.writeheader();writer.writerows(out)
    return len(out),sum(r['status']=='ok' for r in out)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--manifest',type=Path,required=True)
    ap.add_argument('--raw',type=Path,required=True)
    ap.add_argument('--model',choices=sorted(MODELS),required=True)
    ap.add_argument('--run-id',required=True)
    ap.add_argument('--id-col',default='sample_id')
    ap.add_argument('--pred-col',default='pred_label')
    ap.add_argument('--score-col',default='score_vulnerable')
    ap.add_argument('--status-col')
    ap.add_argument('--mapping',type=Path,help='CSV: model_sample_id,sample_id (required when model IDs differ)')
    ap.add_argument('--threshold',type=float,default=0.5)
    ap.add_argument('--out',type=Path,help='Default Results/<model>/<run-id>/predictions.csv')
    args=ap.parse_args()
    out=args.out or Path('Results')/args.model/args.run_id/'predictions.csv'
    count,ok=standardize(args.manifest,args.raw,out,args.model,args.run_id,args.id_col,
                         args.pred_col,args.score_col,args.status_col,args.threshold,args.mapping)
    print(f'Wrote {out}: {ok}/{count} samples have predictions; the rest retain explicit coverage status')

if __name__=='__main__': main()
