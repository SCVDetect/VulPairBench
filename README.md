# VulPairBench

**Reproducible function-level vulnerability detection on vulnerable/patched code pairs.**

VulPairBench brings together three original detector implementations, a common results layout, and lightweight tools for **paired-code evaluation**. It is an experimental research workspace, **not** a validated benchmark release and not yet an executable end-to-end model ensemble. Checkpoint files and datasets must be supplied by their respective owners.

## Start here (first milestone)

1. **Audit the repository** before installing GPU dependencies:
   ```bash
   python scripts/check_workspace.py
   python -m unittest discover -s tests -v
   ```
2. **Review the model requirements** in [Model setup](docs/MODEL_SETUP.md). Install each model in a **separate virtual environment**, using its own `requirements.txt`. SCVdet and VVulDet need Joern and graph-processing assets; LineVul needs its Transformer weights/tokenizer.
3. **Restore checkpoints** in `models/<model>/checkpoints/` and document their origin, architecture, dataset, split, hash, and preprocessing version. **Do not assume** two BigVul checkpoints used identical training partitions.
4. **Establish the test set** by identifying the *official* PairVul test IDs and auditing overlap with each model's training samples. The JSON collected from the Vul-RAG project is not automatically the published 586-pair test split. Details: [Study protocol](docs/WORKFLOW.md).
5. **Dry-run each model entry point** (no GPUs required):
   ```bash
   python scripts/run_model.py --model LineVul --run-id pilot01 --dry-run -- --do_test
   python scripts/run_model.py --model SCVdet --run-id pilot01 --dry-run
   python scripts/run_model.py --model VVulDet --run-id pilot01 --dry-run
   ```
6. **Start a small, checkpoint-validated pilot**, generate function-level predictions for **both** versions of each pair, preserve sample IDs, and verify the actual model input (token truncation; AST/PDG graph extraction; SCVdet inter-function context). Only then evaluate the frozen test set.

## Structure

```text
VulPairBench/
├── models/
│   ├── LineVul/                 # original Transformer implementation and examples
│   ├── SCVdet/                  # original function-relationship GNN implementation
│   └── VVulDet/                 # original domain-aware GNN implementation
│       └── ...                 # each model has checkpoints/ (ignored weights)
├── Results/
│   ├── LineVul/<run-id>/        # generated raw predictions, scores, reports
│   ├── SCVdet/<run-id>/
│   ├── VVulDet/<run-id>/
│   └── comparisons/<run-id>/   # derived pair-level comparisons
├── datasets/
│   ├── raw/                    # ignored locally supplied benchmark files
│   ├── processed/              # ignored manifests and extracted functions
│   └── manifests/              # optional local ID maps (ignored)
├── scripts/                    # dataset, output normalization, benchmark utilities
├── graph_analysis/             # future CPG/AST/CFG/PDG investigations
├── security_evidence/annotations/ # manual security analyses (not published by default)
├── experiments/configs/        # versionable planned configurations
├── docs/                       # protocol, model setup, record of modifications
└── tests/                      # CPU-only integration tests
```

### Model outputs versus checkpoints

**All three actively documented model entry points write result artifacts to `Results/<model>/<run-id>/`** when launched with `VULPAIR_RUN_ID=<run-id>` (or through `scripts/run_model.py`). Results include their original prediction and metric file formats. **Checkpoints are NOT treated as results**: use `models/<model>/checkpoints/`. The model code has been minimally adjusted for these paths; the neural architectures have not been altered.

**Caution:** SCVdet and VVulDet may automatically **train** when an expected checkpoint/configuration is absent. Our wrapper blocks this unless you explicitly opt in. Do not run their original scripts blindly on the server. Running directly from model-specific directories may bypass this protection.

## Quick paired-data preparation (pure Python)

From the repository root after placing the JSON in `datasets/raw/`:

```bash
python scripts/prepare_pairvul.py \
  --input datasets/raw/Linux_kernel_clean_data_top10_CWEs.json \
  --out datasets/processed/top10_audit \
  --export-c
```

Generated: `pairs.csv`, `samples.csv`, `linevul_test.csv`, `dataset_report.json` and optional `c_files/*.c`. Source code is **not normalized or rewritten**; suspect duplicate, identical, whitespace-only and missing-CWE cases receive flags rather than silent deletion. The original code remains in the exported files.

> **Research validity:** `prepare_pairvul.py` does **not** reproduce the authors' historical revert/patch-chain verification or their official training/test split. Do not use the entire JSON as the benchmark without documenting the split and removing overlapping CVEs/functions from training.

## Standard prediction contract

The target form for each **function version** is:

| Column | Meaning |
|---|---|
| `sample_id` | Stable version-specific ID from `samples.csv` |
| `pair_id` | Shared identifier linking `before` and `after` |
| `cve_id` | CVE provenance (metadata only, **not model input**) |
| `version` | `before` or `after` |
| `true_label` | `1` vulnerable before; `0` presumed patched after |
| `pred_label` | Model's binary prediction, selected without test tuning |
| `score_vulnerable` | Optional probability of vulnerability in [0,1] |
| `status` | `ok`, `missing`, or another processing-failure reason |
| `model`, `run_id`, `source_sha256` | Provenance and reproducibility |

Original model CSVs differ. Use the ID-based adapter—**never join model predictions to PairVul by row order**:

```bash
python scripts/standardize_predictions.py \
  --model LineVul --run-id pilot01 \
  --manifest datasets/processed/top10_audit/samples.csv \
  --raw Results/LineVul/pilot01/raw_preds.csv \
  --id-col sample_id --pred-col pred_label --score-col score_vulnerable

python scripts/summarize_pairs.py \
  --predictions Results/LineVul/pilot01/predictions.csv \
  --out-dir Results/comparisons/pilot01/LineVul
```

For SCVdet and VVulDet, preserve a mapping between their internal numeric `function_id`/`func_id` and `sample_id` generated by the dataset preparation. See [Model setup](docs/MODEL_SETUP.md) for the mapping format and output-column differences.

## Study goals

- **RQ1 — Behavior:** do frozen detectors distinguish vulnerable from corresponding patched functions, not merely flip labels?
- **RQ2 — Security evidence:** do the changed condition, data dependency or call actually fix the CVE? Which predictions are false positives, false negatives or inverted?
- **RQ3 — Representation:** does Joern capture the relevant patch, does model preprocessing preserve the relevant AST/CFG/CDG/DDG relations, and does the model use them?
- **RQ4 — Improvement (later):** can offline security knowledge and inter-function context improve the behavior under controlled, leak-free ablations?

This repository sets up **baseline readiness and empirical auditing**. It does not claim a trained knowledge-guided model or security-correct graphs.

## Important notes

- See [Milestone 01 checklist](docs/MILESTONE_01.md), [Workflow and scientific protocol](docs/WORKFLOW.md), [Model setup](docs/MODEL_SETUP.md), [Changes & limitations](docs/CHANGES.md) and [Contributing](CONTRIBUTING.md).
- The original model source and model READMEs are preserved under `models/` with local integration notices. Licenses: **LineVul has its own LICENSE; SCVdet/VVulDet did not include a license file in the supplied ZIP.** Do not assume a single repository-wide license grants rights to redistribute or relicense their code. Check provenance before publishing the repository.
- `Results/` and checkpoint/data payloads are ignored by Git. If publishing derived results, release a vetted subset separately with 

dataset-license and confidentiality checks.

python scripts/check_workspace.py

python -m unittest discover -s tests -v
