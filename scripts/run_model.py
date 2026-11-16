#!/usr/bin/env python3
"""Guarded launcher for original baseline entry points.

Dry-run first. Only use --allow-training after choosing a training protocol.
"""
import argparse
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
MODELS={
    'LineVul':(ROOT/'models/LineVul/linevul','linevul_main.py'),
    'SCVdet':(ROOT/'models/SCVdet/sourcescripts','model/scvuldetect.py'),
    'VVulDet':(ROOT/'models/VVulDet','sourcescripts/train_test.py'),
}


def flag_value(args,flag,default):
    for index,a in enumerate(args):
        if a==flag:
            if index+1>=len(args):raise ValueError('Missing value for '+flag)
            return args[index+1]
        if a.startswith(flag+'='):return a.split('=',1)[1]
    return default


def checkpoint_error(model,run_id,extra):
    model_root=ROOT/'models'/model
    if model=='SCVdet':
        ckpt=model_root/'checkpoints/best_model.ckpt'
        config=model_root/'checkpoints/best_confir.json'
        if not ckpt.is_file() or not config.is_file():
            return f'Existing SCVdet code retrains unless BOTH {ckpt} and {config} exist. Copy validated config for this run.'
    elif model=='VVulDet':
        ckpt=model_root/'checkpoints/model-checkpoint.ckpt'
        if not ckpt.is_file():return f'VVulDet automatically trains if {ckpt} is missing.'
    else:
        if '--do_test' in extra and '--do_train' not in extra:
            output=Path(flag_value(extra,'--output_dir',str(model_root/'checkpoints')))
            if not output.is_absolute():output=MODELS[model][0]/output
            ckpt=output/'checkpoint-best-f1'/flag_value(extra,'--model_name','model.bin')
            if not ckpt.is_file():return f'LineVul --do_test requires existing weights at {ckpt}.'
    return None


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--model',choices=sorted(MODELS),required=True)
    ap.add_argument('--run-id',required=True)
    ap.add_argument('--dry-run',action='store_true')
    ap.add_argument('--allow-training',action='store_true',help='Allow original GNN script to train if its checkpoint/config is absent')
    ap.add_argument('model_args',nargs=argparse.REMAINDER,help='Model flags, after --')
    opts=ap.parse_args()
    import re
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',opts.run_id) or opts.run_id in ('.','..'):
        ap.error('Invalid --run-id')
    extra=opts.model_args
    if extra and extra[0]=='--':extra=extra[1:]
    cwd,entry=MODELS[opts.model]
    command=[sys.executable,'-B',entry,*extra]
    issue=checkpoint_error(opts.model,opts.run_id,extra)
    print('Model:',opts.model,'| Run:',opts.run_id,flush=True)
    print('CWD:',cwd,flush=True)
    print('Command:', ' '.join(command),flush=True)
    print('Results:',ROOT/'Results'/opts.model/opts.run_id,flush=True)
    print('Checkpoint preflight:',issue or 'No obvious missing checkpoint; compatibility not verified',flush=True)
    if opts.dry_run:
        print('DRY RUN ONLY: no model imported, no training or inference executed.')
        return 0
    if issue and not opts.allow_training:
        ap.error(issue+' Pass --allow-training only if you intentionally want the original training fallback.')
    if opts.model=='LineVul' and '--do_train' in extra and not opts.allow_training:
        ap.error('LineVul --do_train requires --allow-training')
    output=ROOT/'Results'/opts.model/opts.run_id
    if output.exists() and any(output.iterdir()):
        ap.error('Output directory already contains files. Choose a fresh --run-id to avoid overwriting data.')
    output.mkdir(parents=True,exist_ok=True)
    env=os.environ.copy();env['VULPAIR_RUN_ID']=opts.run_id
    def gitsha():
        try:return subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,stderr=subprocess.DEVNULL,text=True).strip()
        except Exception:return None
    meta={'model':opts.model,'run_id':opts.run_id,'utc_started':datetime.now(timezone.utc).isoformat(),
          'command':command,'working_directory':str(cwd),'python':sys.version,'git_commit':gitsha(),
          'note':'A launched original baseline does not establish benchmark validity or checkpoint provenance.'}
    (output/'run_metadata.json').write_text(json.dumps(meta,indent=2),encoding='utf-8')
    try:
        result=subprocess.run(command,cwd=cwd,env=env,check=False)
        meta['exit_code']=result.returncode
        return result.returncode
    finally:
        meta['utc_finished']=datetime.now(timezone.utc).isoformat()
        (output/'run_metadata.json').write_text(json.dumps(meta,indent=2),encoding='utf-8')

if __name__=='__main__':sys.exit(main())
