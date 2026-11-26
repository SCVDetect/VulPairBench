# Training SCVdet later: reproducible protocol and safeguards

## What is preserved

The original authors' training path remains under:

- `sourcescripts/processing/process.py`: original dataset loading, diff processing and line-label preparation.
- `sourcescripts/processing/graphdata.py`: source graph generation (`before` and conditional `after`).
- `sourcescripts/processing/graphconstruction.py`: **legacy before-only** node/function embedding and DGL graph caches, for the original paper configuration.
- `sourcescripts/model/scvuldetect.py`: PyTorch Lightning multitask GAT, original losses, selection metrics and hyperparameter grid.

The model architecture (`MultiTaskGAT`), function and node heads, default model grid and original training objectives have not been replaced. Existing `checkpoints/best_model.ckpt` and `best_confir.json` can remain in place. New trial checkpoint directories avoid overwriting each other; best model weights and selected config are stored separately from reporting artifacts. `get_or_compute_v1` now saves the training-derived dependency vector inside the selected checkpoint directory (avoids inadvertently reusing a vector derived from another dataset).

## Reproducing the original training workflow (different from PairVul evaluation)

Use the original dataset resources and paper-compatible dependencies, with training output isolated from the existing benchmark checkpoint:

```bash
cd /home/rz.lekeufack/Rosmael/VulPairBench
source models/SCVdet/.venv/bin/activate

# The original loader expects sourcescripts/storage/external/MSR_data_cleaned.csv
# and the original graph/embedding resources. Verify the exact dataset and split first.
export SCVDET_CHECKPOINT_DIR="$PWD/models/SCVdet/checkpoints/legacy_train_01"
export VULPAIR_RUN_ID="legacy_train_01"
cd models/SCVdet/sourcescripts
python -B processing/process.py
python -B processing/graphdata.py
python -B processing/graphconstruction.py
python -B model/scvuldetect.py
```

**Do not run this blindly against PairVul.** The original loader defaults to `MSR_data_cleaned.csv`, caches a dataset-dependent `minimal_dataset_False.pq`, creates random splits, changes source text and constructs only `before` GNN graphs. These are features of the original training workflow, **not** the evaluation protocol above. Original training also requires line-level targets from patch processing and all embedding resources used by the original feature-generation script, including Word2Vec and SentenceBERT; the inference-only adapter only needs CodeBERT.

The training script uses `SCVDET_CHECKPOINT_DIR` to place the newly trained `best_model.ckpt`, `best_confir.json`, `v1.npy`, and distinct trial checkpoints in a new directory. The `VULPAIR_RUN_ID` environment variable routes logs and metrics to `Results/SCVdet/legacy_train_01/`. If both a checkpoint and best-config JSON already exist in the selected training directory, the original entry point **loads the existing model for testing instead of training**: choose a fresh empty checkpoint directory for a new training attempt.

## Requirements for a scientifically defensible PairVul retraining protocol

1. **Keep a final held-out test split untouched**; create train and validation splits by `cve_id` or stronger repository/time groups, not by individual before/after function. Never split the two versions of the same pair across partitions. Check duplicate functions and overlap with BigVul.
2. **Specify node supervision rather than invent it**: SCVdet's original loss uses `_VULN` for statement/node-level supervision and `_FVULN` for function classification. Pair-level vulnerable/benign labels alone do not identify which nodes are vulnerable. Obtain auditable patch-line or security-evidence annotations; assess noise and ambiguous mappings before training.
3. **Rebuild graph and feature caches per split and preprocessing variant.** The `scripts/run_pairvul.py` graphs are **inference-only** and deliberately contain zero placeholder `_VULN` / `_FVULN` tensors; they are not suitable as labeled training graphs without additional annotation.
4. **Compute `v1` using training data only.** The old `get_or_compute_v1()` function depends on graphs from the `train` partition; do not derive it from evaluation examples or silently reuse a cache from a different dataset. Report function-relationship graph construction, random seeds, and graph coverage.
5. **Match learned model configuration and graph features.** Select CodeBERT/SBERT/Word2Vec, `pdg+raw`, dimensions, learning rate, dropout, and validation metric from the original protocol or explicitly document changes. Do not pick settings based on final-test performance.
6. **Compare to frozen-checkpoint baselines**, and report both sample-level and complete-pair accuracy, score changes, failure coverage, and results per CWE with CVE-level uncertainty estimates.

**Engineering needed before PairVul-specific retraining:** implement a train/val/test manifest adapter with real node supervision, a split-specific function-context (`v1`) builder, and a training dataset that loads version-specific graph keys. The legacy training scripts remain executable for their original dataset and configuration; a completed PairVul retraining adapter is **not** claimed here.
