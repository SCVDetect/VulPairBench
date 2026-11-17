#!/usr/bin/env python3
"""Checkpoint-only, guarded StagedVulBERT function-level inference for VulPairBench.

Run from any directory. No model training. No experiments overwrite each other.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime,timezone

MODEL_ROOT=Path(__file__).resolve().parents[1]
BENCH_ROOT=MODEL_ROOT.parents[1]
DEFAULT_INPUT=BENCH_ROOT/'datasets/processed/pairvul_top10/stagedvulbert_test.csv'
DEFAULT_CHECKPOINT=MODEL_ROOT/'checkpoints/function_level/model_2048.bin'


def sha256_file(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for part in iter(lambda:f.read(1024*1024),b''):
            h.update(part)
    return h.hexdigest()


def make_command(args, result_dir):
    return [sys.executable,'-B','StagedBert_vul.py',
            '--do_test', '--checkpoint_file',str(args.checkpoint.resolve()),
            '--results_dir',str(result_dir), '--cache_dir',str(result_dir/'cache'),
            '--test_data_file',str(args.test_csv.resolve()),
            '--config_name',args.config, '--tokenizer_name',args.tokenizer,
            '--model_name_or_path',args.config,
            '--block_size',str(args.block_size), '--seg_num',str(args.seg_num),
            '--eval_batch_size',str(args.eval_batch_size),
            '--preprocess_workers',str(args.workers),
            '--run_id',args.run_id,
            '--strict_checkpoint']


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--run-id',required=True,help='Unique immutable experiment ID')
    ap.add_argument('--test-csv',type=Path,default=DEFAULT_INPUT)
    ap.add_argument('--checkpoint',type=Path,default=DEFAULT_CHECKPOINT)
    ap.add_argument('--config',default='microsoft/codebert-base',help='Original backbone config or local directory')
    ap.add_argument('--tokenizer',default='microsoft/codebert-base',help='Matching tokenizer or local directory')
    ap.add_argument('--block-size',type=int,default=512,help='Original 512 tokens per segment')
    ap.add_argument('--seg-num',type=int,default=4,help='Original 4 segments = up to ~2048 tokens')
    ap.add_argument('--eval-batch-size',type=int,default=32,help='Original batch size; reduce if OOM')
    ap.add_argument('--workers',type=int,default=4,help='Limit preprocessing processes')
    ap.add_argument('--dry-run',action='store_true')
    args=ap.parse_args(argv)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',args.run_id) or args.run_id in ('.','..'):
        ap.error('Unsafe --run-id')
    if min(args.block_size,args.seg_num,args.eval_batch_size,args.workers)<1:
        ap.error('All numeric settings must be positive')
    run_dir=BENCH_ROOT/'Results/StagedVulBERT'/args.run_id
    command=make_command(args,run_dir)
    print('Workspace:',BENCH_ROOT,flush=True)
    print('Output:',run_dir,flush=True)
    print('Command:',subprocess.list2cmdline(command),flush=True)
    if args.dry_run:
        print('Dry-run: no model imported or result files written.',flush=True)
        return 0
    if not args.test_csv.is_file(): ap.error('Missing input CSV: '+str(args.test_csv))
    if not args.checkpoint.is_file():ap.error('Missing function-level checkpoint: '+str(args.checkpoint))
    if run_dir.exists() and any(run_dir.iterdir()):
        ap.error('Result run directory already populated; use a new --run-id')
    run_dir.mkdir(parents=True,exist_ok=True)
    env=os.environ.copy()
    env['PYTHONPATH']=str(MODEL_ROOT)+os.pathsep+env.get('PYTHONPATH','')
    try:gitsha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=BENCH_ROOT,stderr=subprocess.DEVNULL,text=True).strip()
    except Exception:gitsha=None
    meta={
        'model':'StagedVulBERT', 'task':'function_level_binary_classification',
        'run_id':args.run_id, 'git_commit':gitsha,
        'utc_started':datetime.now(timezone.utc).isoformat(),
        'input_csv':str(args.test_csv.resolve()), 'input_sha256':sha256_file(args.test_csv),
        'checkpoint':str(args.checkpoint.resolve()), 'checkpoint_sha256':sha256_file(args.checkpoint),
        'config':args.config,'tokenizer':args.tokenizer,
        'block_size':args.block_size,'seg_num':args.seg_num,
        'eval_batch_size':args.eval_batch_size,'preprocess_workers':args.workers,
        'checkpoint_loading':'strict','command':command,
        'note':'Baseline checkpoint-only evaluation; no fine-tuning on PairVul, no overlap audit performed here.'
    }
    path=run_dir/'run_metadata.json'
    path.write_text(json.dumps(meta,indent=2)+'\n')
    try:
        result=subprocess.run(command,cwd=MODEL_ROOT/'Entry',env=env,check=False)
        meta['exit_code']=result.returncode
        return result.returncode
    finally:
        meta['utc_finished']=datetime.now(timezone.utc).isoformat()
        path.write_text(json.dumps(meta,indent=2)+'\n')

if __name__=='__main__':sys.exit(main())
