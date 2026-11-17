"""Non-invasive VulPairBench evaluation artifact helpers.

This module never changes model outputs; it only records predictions and provenance.
"""
import csv
import hashlib
import json
import math
from pathlib import Path


def cache_file(file_path, tokenizer, args, file_type):
    """Content- and configuration-addressed pickle to avoid stale cached features."""
    if getattr(args, 'cache_dir', None):
        path = Path(file_path).resolve()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        tokenizer_id = getattr(tokenizer, 'name_or_path', type(tokenizer).__name__)
        signature = json.dumps({
            'version': 'stagedvulbert-v1', 'input_sha256': digest,
            'tokenizer': str(tokenizer_id), 'vocabulary_size': len(tokenizer),
            'block_size': args.block_size, 'seg_num': args.seg_num,
        }, sort_keys=True)
        key = hashlib.sha256(signature.encode()).hexdigest()[:20]
        output = Path(args.cache_dir) / (file_type + '_' + key + '_lp.pkl')
        output.parent.mkdir(parents=True, exist_ok=True)
        return str(output)
    path = file_path[:-4] if file_path.endswith('.csv') else file_path
    return path + '_lp.pkl'  # Original behavior outside guarded runner


def load_weights(model, checkpoint, device, strict=False, logger=None):
    """Make incomplete weight loading visible; strict mode rejects any mismatch."""
    import torch
    checkpoint = Path(checkpoint)
    if not checkpoint.is_file():
        raise FileNotFoundError('Missing checkpoint: ' + str(checkpoint))
    state = torch.load(str(checkpoint), map_location=device)
    if isinstance(state, dict) and 'state_dict' in state:
        state = state['state_dict']
    mismatched = model.load_state_dict(state, strict=False)
    missing, unexpected = list(mismatched.missing_keys), list(mismatched.unexpected_keys)
    message = f'Checkpoint {checkpoint}: {len(missing)} missing and {len(unexpected)} unexpected model parameters'
    print(message, flush=True)
    if logger: logger.warning('%s; missing=%s; unexpected=%s', message, missing[:50], unexpected[:50])
    if strict and (missing or unexpected):
        raise RuntimeError(message + '\nMissing: '+repr(missing[:20])+'\nUnexpected: '+repr(unexpected[:20]))
    return {'checkpoint':str(checkpoint.resolve()), 'missing_keys':missing, 'unexpected_keys':unexpected}


def write_evaluation(args, dataset, logits, truths, threshold, metrics):
    """Export one observation per original CSV row, with preserved IDs and visibility data.

    logits[:, 1] is the probability of class 1 from the unmodified model.
    """
    import pandas as pd
    import numpy as np
    results_dir = getattr(args, 'results_dir', None)
    if not results_dir: return
    result_dir = Path(results_dir)
    result_dir.mkdir(parents=True, exist_ok=True)
    inputs = pd.read_csv(args.test_data_file, keep_default_na=False)
    if len(inputs) != len(logits) or len(inputs) != len(truths) or len(dataset.examples) != len(inputs):
        raise RuntimeError('Prediction/CSV/dataset length mismatch. Refusing to emit an incorrectly aligned output.')
    required = {'sample_id','pair_id','cve_id','version','target'}
    missing = required - set(inputs.columns)
    if missing:
        raise ValueError('Evaluation CSV is missing required audit fields: '+repr(sorted(missing)))
    if inputs.sample_id.astype(str).duplicated().any():
        raise ValueError('Duplicate sample_id in test CSV')
    input_targets = pd.to_numeric(inputs['target'], errors='raise').to_numpy(dtype=int)
    if not np.array_equal(input_targets, np.asarray(truths, dtype=int)):
        raise RuntimeError('Model labels differ from input CSV labels; refusing misaligned output')
    scores = np.asarray(logits)[:,1]
    if not np.isfinite(scores).all() or np.any(scores < 0) or np.any(scores > 1):
        raise RuntimeError('Class-1 score is not a finite probability')
    raw=[]
    standardized=[]
    for i, example in enumerate(dataset.examples):
        original_count = max(0, len(example.input_tokens)-2)
        visible_count = sum(max(0, len(f.row_idx)-1) for f in example.tokens_features if f is not None)
        if visible_count > original_count:
            raise RuntimeError('Feature visible token count exceeds original; investigate segmentation')
        sample = inputs.iloc[i]
        probability = float(scores[i]); pred = int(probability > threshold)  # original code uses strict >
        fields={'model':'StagedVulBERT','run_id':str(getattr(args,'run_id','manual')),
                'sample_id':str(sample['sample_id']),'pair_id':str(sample['pair_id']),
                'cve_id':str(sample['cve_id']),'version':str(sample['version']),
                'true_label':int(truths[i]),'pred_label':pred,
                'score_vulnerable':probability,'status':'ok',
                'source_sha256':str(sample.get('source_sha256',''))}
        standardized.append(fields)
        raw.append(dict(fields, original_tokens=original_count,
                        visible_tokens=visible_count, truncated=(visible_count < original_count),
                        used_segments=sum(f is not None for f in example.tokens_features)))
    pd.DataFrame(standardized).to_csv(result_dir/'predictions.csv',index=False)
    pd.DataFrame(raw).to_csv(result_dir/'raw_preds.csv',index=False)
    def valid_json(x):
        if isinstance(x, float) and not math.isfinite(x): return None
        return x
    metric_payload={k:valid_json(v) for k,v in metrics.items()}
    metric_payload.update({'samples':len(standardized), 'threshold':threshold,
                           'truncated_samples':sum(r['truncated'] for r in raw),
                           'note':'Original class-1 probabilities; labels follow original > threshold policy. No checkpoint training occurred here.'})
    (result_dir/'metrics.json').write_text(json.dumps(metric_payload,indent=2,allow_nan=False)+'\n')
