# Model setup and checkpoint placement

This document describes **what the uploaded code actually does**. Commands are starting points, **not** evidence that the old environments, pretrained weights or server are operational. Use separate Python environments to avoid incompatible versions of Torch/DGL/PyTorch Lightning/Transformers.

## Path and execution matrix

| Model | Original entry point | Launch directory (when running manually) | Current output folder | Checkpoint expectation |
|---|---|---|---|---|
| LineVul | `linevul/linevul_main.py` | `models/LineVul/linevul` | `Results/LineVul/$VULPAIR_RUN_ID/` | `models/LineVul/checkpoints/checkpoint-best-f1/<model_name>` (if `--output_dir` omitted) |
| SCVdet | `sourcescripts/model/scvuldetect.py` | `models/SCVdet/sourcescripts` | `Results/SCVdet/$VULPAIR_RUN_ID/` | `models/SCVdet/checkpoints/best_model.ckpt` **and** `models/SCVdet/checkpoints/best_confir.json` |
| VVulDet | `sourcescripts/train_test.py` | `models/VVulDet` | `Results/VVulDet/$VULPAIR_RUN_ID/` | `models/VVulDet/checkpoints/model-checkpoint.ckpt` |

All original script outputs reachable through `utls.outputs_dir()`/`imp.outputs_dir()` use the shared destination. Training caches, Joern installations and intermediate graph data remain within each model's `sourcescripts/storage/`. Alternative/legacy SCVdet trainer entry points were updated to use the central output directory helper and centralized checkpoint path where explicitly present, but have **not** been executed against the original dependencies.

Use a distinct `VULPAIR_RUN_ID` for each experiment, dataset version, checkpoint, seed or preprocessing revision. Reusing a run ID may overwrite previous files and invalidate results. The wrapper accepts `--run-id` and creates metadata for the attempt.

## 1. LineVul — function-level sequence model

- Original implementation under `models/LineVul/`, with a preserved upstream README, LICENSE, tokenizers and examples.
- Install from `models/LineVul/requirements.txt` in a dedicated virtual environment. Use a Transformer base model and matching tokenizer consistent with the original checkpoint.
- The **tested function inference** entry point is `linevul_main.py --do_test` (not the line-localization task). The original code loads weights under `--output_dir/checkpoint-best-f1/<model_name>`.
- We added `--results_dir`, defaulting to `Results/LineVul/<run-id>`, and made `flaw_line`/`flaw_line_index` optional for function-level paired test CSVs. With `--write_raw_preds`, its output CSV now contains `raw_preds`, `pred_label`, `true_label`, `score_vulnerable`, and any incoming `sample_id`/`pair_id`/`version` metadata.
- **Caution:** CodeBERT token truncation can remove the patch! Record the fraction of security-relevant changed tokens falling after the chosen block size. Do not silently truncate in one model but omit failures in another.

Illustrative CLI after obtaining a checkpoint and its matching base config/tokenizer (edit paths as needed):

```bash
python scripts/run_model.py --model LineVul --run-id pilot01 -- \
  --do_test --write_raw_preds \
  --model_name_or_path microsoft/codebert-base \
  --tokenizer_name microsoft/codebert-base \
  --test_data_file ../../../datasets/processed/top10_audit/linevul_test.csv \
  --block_size 512
```

**Path note:** `--test_data_file` in this example is relative to the LineVul working directory `models/LineVul/linevul`. The wrapper intentionally uses that directory so the preserved relative tokenizer paths remain valid. Check that your restored checkpoint matches the architecture and base configuration; the example model identifier is **not** a declaration that a compatible checkpoint has been provided.

## 2. SCVdet — GNN with function relationships

- Core trainer/test script: `models/SCVdet/sourcescripts/model/scvuldetect.py`.
- Original README describes Joern, graph creation, CodeBERT/Word2Vec/SBERT embeddings, and the test/evaluation pipeline; those steps remain model-specific.
- `scvuldetect.py` checks for both `best_model.ckpt` and `best_confir.json` and **trains** if either is missing. Recover/check both before inference; the wrapper requires both unless `--allow-training` is passed.
- Original function-level output has `function_id`, `func_level_pred` (actual graph classifier decision), `prediction` (aggregate of node flags), and now `score_vulnerable` (softmax positive-class score) in `function_level_predictions.csv`. For the main paired benchmark, use `func_level_pred`, **not** `prediction`, unless explicitly testing the node-aggregation rule.
- The original function-relationship construction may require data from other functions or global vector `v1`; passing an isolated function is **not necessarily equivalent** to the published SCVdet configuration. Document this and do not label a reduced-context run as full SCVdet.

Model ID mapping is essential. A CSV such as:

```csv
model_sample_id,sample_id
12345,p000000_15f2a33777be__before
12346,p000000_15f2a33777be__after
```

Here IDs are *illustrative only*. Construct the actual mapping from the graph-building manifest, not from CSV row positions or inference order.

```bash
python scripts/standardize_predictions.py \
  --model SCVdet --run-id pilot01 \
  --manifest datasets/processed/top10_audit/samples.csv \
  --raw Results/SCVdet/pilot01/function_level_predictions.csv \
  --id-col function_id --pred-col func_level_pred \
  --score-col score_vulnerable --mapping datasets/manifests/scvdet_id_map.csv
```

## 3. VVulDet — domain-aware GNN

- Original training/inference script: `models/VVulDet/sourcescripts/train_test.py`.
- Checkpoint path now defaults to `models/VVulDet/checkpoints/model-checkpoint.ckpt`, separated from `Results/`. If absent, **the original code trains a new checkpoint**; the wrapper guards against accidental training.
- Original graph extraction and pretrained CodeBERT asset acquisition run in this model's existing `zrun/` and `sourcescripts/` scripts. Check actual downloads, graph type, and embeddings before inference.
- Original `function_level_predictions.csv` includes `func_id`, `func_pred`, and now retains `func_prob_1` as the positive-class confidence for later pair analysis. Previous versions dropped the probability column.

```bash
python scripts/standardize_predictions.py \
  --model VVulDet --run-id pilot01 \
  --manifest datasets/processed/top10_audit/samples.csv \
  --raw Results/VVulDet/pilot01/function_level_predictions.csv \
  --id-col func_id --pred-col func_pred \
  --score-col func_prob_1 --mapping datasets/manifests/vvuldet_id_map.csv
```

## Reproducibility and safety notes

1. Preserve the model, tokenizer, data-processing version, Joern version, graph representation, and checkpoint *hash* in your run notebook/metadata. A filename alone does not identify a model.
2. For initial smoke tests, use **frozen weights** and the threshold chosen without using PairVul test labels. There is **no** training/checkpoint bundled in the ZIP.
3. Evaluate both versions separately; preserve pair IDs even if one graph or token sequence fails. Report coverage and failure reasons for every model.
4. Do not send the test CVE description, ground-truth CWE, patch, or before/after label into the classifier as feature inputs, unless evaluating a clearly identified privileged-information setting.
5. The codebase includes older scripts and original research examples. Only the three entry points in the matrix are primary integration targets for the first milestone.
