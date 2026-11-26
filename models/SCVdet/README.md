# SCVdet — VulPairBench paired-code runner

This folder retains the authors' **SCVdet** GNN architecture and original training scripts, with an additional **inference-only paired benchmark adapter** in [`scripts/run_pairvul.py`](scripts/run_pairvul.py). Source: [original implementation](README_UPSTREAM.md). This distribution preserves the training entry point but **does not bundle datasets, embeddings, checkpoints, or Joern executables**.

The new adapter evaluates **both versions of every pair** (`before` = label 1, `after` = label 0) using the same source-code samples as LineVul and StagedVulBERT. Crucially, it does *not* call the legacy `dataset()` loader, which uses BigVul data, transforms source code, and assigns its own splits. It does *not* call the legacy `graphconstruction.py` runner, which builds model graphs from `before` only.

## Quick start (from VulPairBench root)

Activate your existing **SCVdet virtual environment**. For a preflight report, no DGL or GPU is required:

```bash
python models/SCVdet/scripts/run_pairvul.py --stage check
```

Expected local assets:

- `models/SCVdet/checkpoints/best_model.ckpt` (trusted SCVdet Lightning checkpoint). `best_confir.json` is only needed if configuration is absent from the checkpoint hyperparameters.
- `models/SCVdet/sourcescripts/storage/cache/embedmodel/CodeBERT/` (local HF model, including `config.json`; other supported paths: `cache/embedmodel/`, `Codebert/`, `codebert/`). Use `--codebert-path ...` if different.
- `models/SCVdet/sourcescripts/storage/external/joern-cli/joern`. Use `--joern ...` if different.
- `datasets/processed/pairvul_top10/samples.csv` prepared by the VulPairBench `scripts/prepare_pairvul.py`, with columns `sample_id`, `pair_id`, `version`, `label`, `processed_func` and optionally `source_sha256`, `cve_id`.

**Pilot:** start with five complete pairs, keeping pilot caches isolated from the full experiment:
 
```bash
python models/SCVdet/scripts/run_pairvul.py \
  --stage all \
  --samples datasets/processed/pairvul_top10/samples.csv \
  --dataset-tag pairvul_top10_pilot5 \
  --run-id pairvul_top10_scvdet_pilot5 \
  --limit-pairs 5 --strict
```

**Full dataset** (2,740 pairs, 5,480 graphs; extraction/embedding can take a long time):

```bash
python models/SCVdet/scripts/run_pairvul.py \
  --stage all \
  --samples datasets/processed/pairvul_top10/samples.csv \
  --dataset-tag pairvul_top10 \
  --run-id pairvul_top10_scvdet_01
```

For restarts or debugging, use distinct stages with the **same** `--dataset-tag` and `--run-id`:

```bash
python models/SCVdet/scripts/run_pairvul.py --stage prepare --dataset-tag pairvul_top10 --run-id pairvul_top10_scvdet_01
python models/SCVdet/scripts/run_pairvul.py --stage extract --dataset-tag pairvul_top10 --run-id pairvul_top10_scvdet_01
python models/SCVdet/scripts/run_pairvul.py --stage build   --dataset-tag pairvul_top10 --run-id pairvul_top10_scvdet_01
python models/SCVdet/scripts/run_pairvul.py --stage predict --dataset-tag pairvul_top10 --run-id pairvul_top10_scvdet_01
```

python models/SCVdet/scripts/run_pairvul.py \
  --stage predict \
  --dataset-tag pairvul_top10 \
  --run-id pairvul_top10_scvdet_cpu01 \
  --device cpu

`prepare` copies the **original code, including comments and preprocessor directives**, into independent `before/` and `after/` `.c` files. Paths are derived from a hash of the pair ID (not directly from potentially unsafe IDs), and all original IDs are retained in the manifest.

`extract` invokes Joern once per `.c` file and checks for `.nodes.json` and `.edges.json`. It writes `joern_status.csv`, including failures. `build` uses SCVdet's original `feature_extraction(..., "pdg+raw")`, local CodeBERT embeddings, graph orientation and 100-dimensional random node features; it writes `graph_status.csv`. `predict` loads the **frozen checkpoint strictly**, refuses to recompute the model's training-derived `v1` vector on test samples, uses the **function-logit argmax** for classification, and records the node-aggregation decision only as secondary diagnostics.

You can restart any stage. Existing Joern outputs and validated graph caches are reused unless you specify `--rebuild`. **Never reuse the same `--dataset-tag` after changing source code, checkpoint-relevant preprocessing, or embedding assets**; give it a new tag. `--rebuild` refreshes current inputs but does not erase old artifacts. `--strict` stops after a stage that has any failures; without it, failed samples and incomplete pairs are explicitly reported, never silently counted as evaluated.

> **Do not run** the root `python scripts/run_model.py --model SCVdet` command for this paired test. That existing generic launcher targets the legacy `model/scvuldetect.py` workflow, not this new pair-aware pipeline. Use `models/SCVdet/scripts/run_pairvul.py` as above.

## Files and results

```text
VulPairBench/
├── datasets/processed/pairvul_top10/samples.csv             # Common benchmark input
├── models/SCVdet/
│   ├── scripts/run_pairvul.py                                # New paired workflow
│   ├── checkpoints/best_model.ckpt                           # Supply separately
│   └── sourcescripts/storage/
│       ├── external/joern-cli/                               # Supply separately
│       ├── cache/embedmodel/CodeBERT/                         # Supply separately
│       ├── processed/<dataset-tag>/
│       │   ├── before/<pair-hash>__before.c[.nodes.json, .edges.json]
│       │   ├── after/<pair-hash>__after.c[.nodes.json, .edges.json]
│       │   └── sample_manifest.csv
│       └── cache/Graph/<dataset-tag>_svuldet_codebert_pdg+raw/
│           └── <graph-id>                                    # DGL serialized graph per sample
└── Results/SCVdet/<run-id>/
    ├── joern_status.csv
    ├── graph_status.csv
    ├── predictions.csv                                       # Common benchmark schema
    ├── raw_preds.csv
    ├── function_level_predictions.csv
    ├── prediction_failures.csv
    ├── metrics.json
    └── run_metadata.json
```

In `predictions.csv`, `sample_id`, `pair_id`, and `version` keep the vulnerable and patched samples distinct. `pred_label` / `func_level_pred` come from **SCVdet function logits**. `score_vulnerable` is class-1 softmax. `node_aggregate_pred` is the model's alternative *any-positive-node* rule and must **not** replace the primary function-level decision without an explicit experimental variant.

**After inference**, use the shared evaluator from VulPairBench root:

```bash
python scripts/summarize_pairs.py \
  --predictions Results/SCVdet/pairvul_top10_scvdet_01/predictions.csv \
  --out-dir Results/comparisons/pairvul_top10_scvdet_01/SCVdet
```

`metrics.json` already reports pair coverage and class-level metrics, but using the exact same common evaluator as the other models is preferable for the study. Do **not** compute pair accuracy on only successful graphs without simultaneously reporting missing-graph coverage.

## Important scientific limitations

1. **Compatibility has not been proven on your server.** Python syntax, CPU-side preparation and mapping tests were run; the supplied archive contains no trained checkpoint, Joern binary, local embedding assets or DGL environment. Verify the first ten graphs and classification results before scaling up.
2. **Joern version matters.** The original `storage/external/get_func_graph.scala` is preserved; an updated Joern may require Scala-script changes. Failed extraction is recorded, not masked.
3. **Source preprocessing differs from the original SCVdet training data.** The paired workflow preserves source comments and formatting; the original preprocessing may remove comments and reconstruct patch lines. This is an intentional *raw-code baseline*, not proof of a matched training–test preprocessing regime. See [`docs/EXPERIMENT_PROTOCOL.md`](docs/EXPERIMENT_PROTOCOL.md).
4. **Original graph construction uses randomly generated node features.** The adapter seeds these per sample so repeated runs reuse the same features. This improves reproducibility, but it is not a claim of identical runtime random draws to the original training experiment. The graph cache is input-specific.
5. **No test-derived labels or learned context are used.** `_VULN` and `_FVULN` are placeholders in inference graphs; the original model's forward pass does not use them. The learned `v1` is recovered *only from the checkpoint*. Separate patches can change the graph embeddings and thus the predictions, but no trainable parameters are updated.
6. **Original `_LINE` behavior is preserved.** SCVdet's upstream `feature_extraction()` returns Joern node IDs in a field named `lineno`; those are **not reliable source line numbers**. Do not interpret the `_LINE` field as patch-line coverage before a dedicated mapping fix.
7. **Benchmark independence and leakage still need auditing.** These are exploratory PairVul candidate samples, not automatically the official held-out 586-pair split. Audit CVE and code overlap with the checkpoint training set before publication claims.

## Training in a later phase

The original training implementation is still present at `sourcescripts/model/scvuldetect.py`. The paired adapter does not train and will never silently start training. See **[`docs/TRAINING.md`](docs/TRAINING.md)** for how to reproduce legacy training using separate datasets, train/validation/test groups, annotated vulnerable lines, and dedicated checkpoint directories, plus the additional work needed for pair-aware training.

## Infrastructure tests

```bash
python -m unittest discover -s models/SCVdet/tests -v
python -m compileall -q models/SCVdet/scripts models/SCVdet/sourcescripts
```

For original authors' documentation and attribution, see [README_UPSTREAM.md](README_UPSTREAM.md).
