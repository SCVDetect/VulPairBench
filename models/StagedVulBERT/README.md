# StagedVulBERT in VulPairBench

> **Status:** Baseline code packaged and statically tested; no checkpoints supplied and no GPU inference was run. Research baseline: [StagedVulBERT](https://github.com/YuanJiangGit/StagedVulBERT) (Jiang et al., IEEE TSE 2024). This module is the user's supplied source snapshot. See [`README_UPSTREAM.md`](README_UPSTREAM.md) for authors' original instructions. No new license is asserted for the authors' code.

## Layout after extracting the ZIP

```text
VulPairBench/
├── models/
│   └── StagedVulBERT/
│       ├── Entry/                      # Authors' function and line-level entry points + export helpers
│       ├── Models/                     # Unmodified neural network architecture
│       ├── MSP_Pretraining Code/       # Original pretraining source (not needed for inference)
│       ├── resource/                   # Tokenizer resources; author download placeholders
│       ├── checkpoints/                # External checkpoint files; excluded from Git
│       │   ├── function_level/        # model_2048.bin (user provides later)
│       │   ├── line_level/
│       │   └── pretraining/
│       ├── scripts/
│       │   ├── prepare_input.py       # Adapts existing samples.csv, preserves code
│       │   ├── run_pairvul.py         # Guarded, strict checkpoint-only function inference
│       │   └── validate_setup.py
│       ├── README_VULPAIRBENCH.md
│       └── requirements-inference.txt
├── datasets/
│   └── processed/pairvul_top10/
│       ├── samples.csv               # Existing dataset preparation output
│       └── stagedvulbert_test.csv     # This module's model-specific input
└── Results/StagedVulBERT/<run-id>/
    ├── predictions.csv                # VulPairBench schema for paired evaluation
    ├── raw_preds.csv                  # Scores + actual original/visible token counts
    ├── metrics.json                   # Original function-level metrics
    ├── run_metadata.json              # Input/checkpoint hashes and configuration
    ├── logs/                          # Evaluation logs
    └── cache/                         # Content/config-addressed feature cache
```

The model writes **prediction outputs** to the shared `Results/` directory. **Checkpoint files are never put under Results** by the guarded runner.

## 1 — Environment (recommended Python 3.10)

```bash
cd VulPairBench/models/StagedVulBERT
python3.10 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-inference.txt
python scripts/validate_setup.py
```

The original `README_UPSTREAM.md` lists conflicting `transformers==4.34.0` and `tokenizers==0.15.1`; this inference file uses a compatible 0.14.1 version. The line-level architecture may require additional packages from the original requirements (e.g. `libclang`, `captum`) for auxiliary analysis; do not infer that function-level environment covers all author experiments.

**Backbone configuration:** The authors' default `resource/codebert-base` is an empty download placeholder in this snapshot. The wrapper points to `microsoft/codebert-base` for configuration and tokenizer; the model's initialized parameters are replaced by your fine-tuned checkpoint. For offline operation, supply verified local backbone config/tokenizer directories with `--config` and `--tokenizer`. Check original published tokenizer/config provenance before interpreting results.

## 2 — Prepare test data (no data modification)

First obtain `datasets/processed/pairvul_top10/samples.csv` using your existing root command `python scripts/prepare_pairvul.py ...`.

Then, from **VulPairBench root**:

```bash
python models/StagedVulBERT/scripts/prepare_input.py \
  --samples datasets/processed/pairvul_top10/samples.csv \
  --out datasets/processed/pairvul_top10/stagedvulbert_test.csv
```

The adapter copies `processed_func` exactly into the author's `func_before`, copies class `target` unchanged, and retains `sample_id`, `pair_id`, `cve_id`, `version` and `source_sha256`. The original JSON patch and CWE labels are **not supplied to the classifier as privileged input**. Since this source dataset lacks ground-truth vulnerable-line indices, `flaw_line_index` is empty. **This CSV is valid for function-level evaluation only.**

## 3 — Supply the correct weights

Place the authors' **BigVul fine-tuned coarse/function-level** `.bin` at:

`models/StagedVulBERT/checkpoints/function_level/model_2048.bin`

Author-provided download link (not independently validated in this package):
https://drive.google.com/file/d/1Q4_jjXQydP5oyHsLAWnkhlvEcFjVu4fj/view

Do **not** confuse this with the MSP-only pretrained weights or the fine/line-level checkpoint. The runner refuses to run without a checkpoint. It also refuses incomplete checkpoint loading.

## 4 — Run a no-side-effects dry run

```bash
python models/StagedVulBERT/scripts/run_pairvul.py \
  --run-id pairvul_top10_staged_01 --dry-run
```

Then run from the VulPairBench root with the StagedVulBERT virtual environment active:

```bash
python models/StagedVulBERT/scripts/run_pairvul.py \
  --run-id pairvul_top10_staged_01 \
  --eval-batch-size 4
```

The original batch size is 32, and original function model settings are **`block_size=512`, `seg_num=4`, 12 attention heads, 6 hidden layers, 0.5 decision threshold**. Here `--eval-batch-size 4` reduces memory use for a first run; it does **not** change model weights or input length. For an exact default-configuration run, omit `--eval-batch-size`. Further customizations are available through `--help`. The tool never trains a model or silently falls back to random initialization.

Use a new run ID for every repetition. The runner computes input and checkpoint SHA256 hashes, records settings, uses strict checkpoint loading, and will not overwrite a populated run directory. **The entry point preserves the author's original class probability convention (`score_vulnerable` is class 1, predictions use `> 0.5`).**

## 5 — Analyze and compare

`Results/StagedVulBERT/<run-id>/predictions.csv` uses:

`model,run_id,sample_id,pair_id,cve_id,version,true_label,pred_label,score_vulnerable,status,source_sha256`

`raw_preds.csv` additionally records `original_tokens`, `visible_tokens`, `truncated`, `used_segments` as actually constructed by the model's segment encoder, supporting patch-visibility experiments. Do not conflate **source-token counts** with **actual security-patch visibility**.

The original root `scripts/summarize_pairs.py` can be run directly with the predictions file:

```bash
python scripts/summarize_pairs.py \
  --predictions Results/StagedVulBERT/pairvul_top10_staged_01/predictions.csv \
  --out-dir Results/comparisons/pairvul_top10_staged_01/StagedVulBERT
```

**Integration note:** The previously prepared `scripts/standardize_predictions.py` accepts only LineVul/SCVdet/VVulDet. You do not need that script because StagedVulBERT directly generates the same `predictions.csv` schema. If you later want to use it anyway, add `StagedVulBERT` to that script's model allowlist and test it.

## 6 — Research safeguards

- This evaluation uses a **BigVul-trained checkpoint**, not the Vul-RAG authors' re-fine-tuned baseline; report that distinction.
- The Top-10 CWE JSON contains **2,740 candidate pairs**; it is not automatically the official **586-pair held-out PairVul test partition**. Audit the split and training overlap before publication claims.
- Checkpoint accuracy must first be verified on the checkpoint authors' original test set; an inference run is not a reproduction claim.
- The wrapper performs **no comment removal, input normalization, data resampling or label rewriting**. This permits a controlled comparison to the LineVul raw-input baseline.
- A function can be truncated despite a nonzero `used_segments` count. Use a patch-line visibility audit to establish security-relevant observability, rather than declaring all visible code patches security-relevant.
- The original repository has **no top-level license file in the supplied snapshot**. Verify copyright/license terms before publishing or redistributing modified versions of the source; retain attribution and this change log.

## Source changes made for VulPairBench

- `Entry/StagedBert_vul.py`: optional `--checkpoint_file`, `--results_dir`, `--cache_dir`, `--strict_checkpoint`; exports test probabilities and metrics while preserving model computation.
- `Entry/StagedBert_line_vul.py`: optional explicit fine/coarse checkpoints; separates run logging/metrics and checkpoint directories. **Full line-level prediction CSV not yet implemented or validated.**
- `Entry/vulpair_utils.py`: checkpoint verification, unique cache keys, deterministic ID-aligned CSV export, segmentation coverage.
- `scripts/`: guarded inference runner, input adapter, environment diagnostics.
- `Models/`: unchanged architecture/weights code.

The supplied archive did not include a trained `.bin`, so no end-to-end GPU inference could be validated here. See test results in the accompanying assistant message.
