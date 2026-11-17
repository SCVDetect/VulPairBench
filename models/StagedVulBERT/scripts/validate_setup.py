#!/usr/bin/env python3
"""Zero-dependency readiness inspection (does not import torch)."""
from pathlib import Path
import csv
import json

model=Path(__file__).resolve().parents[1]
bench=model.parents[1]
items={
    'model_directory':str(model),
    'repo_directory':str(bench),
    'is_under_models':model.parent.name=='models',
    'function_entry':(model/'Entry/StagedBert_vul.py').is_file(),
    'line_entry':(model/'Entry/StagedBert_line_vul.py').is_file(),
    'model_definition':(model/'Models/StagedModel_vul.py').is_file(),
    'checkpoint_exists':(model/'checkpoints/function_level/model_2048.bin').is_file(),
    'test_input_exists':(bench/'datasets/processed/pairvul_top10/stagedvulbert_test.csv').is_file(),
    'results_parent':str(bench/'Results/StagedVulBERT'),
}
if items['test_input_exists']:
    with (bench/'datasets/processed/pairvul_top10/stagedvulbert_test.csv').open(encoding='utf-8',newline='') as f:
        reader=csv.reader(f);items['test_header']=next(reader,None)
print(json.dumps(items,indent=2))
if not items['is_under_models']:
    raise SystemExit('Extract StagedVulBERT/ directly into VulPairBench/models/.')
