# FiCoVuL for VulPairBench

**Status:** optional *Phase B* graph-model replication and potential security-knowledge intervention. It is **not** one of the three initial frozen-checkpoint failure-analysis baselines (LineVul, StagedVulBERT, SCVdet).

This folder can be extracted into `VulPairBench/models/FiCoVuL/`. The upstream architecture, training scripts, dataset logic, config defaults, and graph export scripts are retained. The new `scripts/run_pairvul.py` is a separate, conservative **inference adapter**, not a claim that the upstream model is already reproducible. **No pretrained FiCoVuL checkpoint or original training vocabularies were present in the uploaded archive.**

## Directory map

```text
VulPairBench/
├── models/
│   └── FiCoVuL/
│       ├── FiCoVuL/                 # ORIGINAL model/training/testing code
│       │   ├── configs/config.json5 # ORIGINAL configuration (unchanged)
│       │   ├── models/
│       │   ├── dataset/
│       │   ├── train3.py
│       │   └── test3.py
│       ├── Doxygen/                 # ORIGINAL extraction source, sans bundled Joern binaries
│       ├── scripts/run_pairvul.py  # NEW paired-code dataset / graph / prediction adapter
│       ├── checkpoints/            # private weights + training vocab files (ignored)
│       ├── work/                   # generated source files/graphs/caches (ignored)
│       ├── docs/
│       ├── tests/
│       ├── README_UPSTREAM.md      # original README, unmodified
│       └── requirements.txt       # original dependency list, unmodified
├── datasets/processed/pairvul_top10/samples.csv
└── Results/FiCoVuL/<run-id>/      # shared experiment outputs
```

## First steps (work without a checkpoint)

From the **VulPairBench repository root**:

```bash
python models/FiCoVuL/scripts/run_pairvul.py --stage check

python models/FiCoVuL/scripts/run_pairvul.py \
  --stage prepare \
  --samples datasets/processed/pairvul_top10/samples.csv \
  --dataset-tag pairvul_top10_pilot5 \
  --limit-pairs 5
```

The second command creates ten **verbatim**, version-separated `.c` functions (five `before`, five `after`) and a stable `work/pairvul_top10_pilot5/manifest.csv`. It does **not** run Joern, construct graphs or load a model.

## Steps that require recovered training artifacts

Recover a **trusted** original checkpoint and the original training vocabularies (from the same training run):

```text
models/FiCoVuL/checkpoints/function_level/model.pth
models/FiCoVuL/checkpoints/vocab/node_type_dict.pkl
models/FiCoVuL/checkpoints/vocab/word_lexical_dict.pkl
models/FiCoVuL/checkpoints/vocab/word_value_dict.pkl
models/FiCoVuL/checkpoints/vocab/most_common_function_names.txt
```

**Joern stage:** FiCoVuL's upstream graph pipeline consumes more than raw C snippets: it relies on Joern, original preprocessing/annotation metadata, and a specific graph JSON schema. An automated standalone-code Joern adapter is **not included** as validated functionality. Follow `docs/REPLICATION.md`. Place the *verified, upstream-format graph JSON* for each prepared `graph_id` into:

`models/FiCoVuL/work/<dataset-tag>/joern/<graph_id>.json`

Once the graph exporter has been reproduced on a small pilot, run:

```bash
python models/FiCoVuL/scripts/run_pairvul.py \
  --stage build \
  --dataset-tag pairvul_top10_pilot5 \
  --checkpoint models/FiCoVuL/checkpoints/function_level/model.pth \
  --vocab-dir models/FiCoVuL/checkpoints/vocab --strict

python models/FiCoVuL/scripts/run_pairvul.py \
  --stage predict \
  --dataset-tag pairvul_top10_pilot5 \
  --run-id pairvul_top10_ficovul_pilot5 \
  --checkpoint models/FiCoVuL/checkpoints/function_level/model.pth \
  --vocab-dir models/FiCoVuL/checkpoints/vocab \
  --device cpu --strict
```

Successful predictions will be exported to `Results/FiCoVuL/<run-id>/predictions.csv`, alongside `raw_preds.csv`, `metrics.json`, `prediction_failures.csv` and `run_metadata.json`, with the same key columns used by the other VulPairBench models. **The model and graph extraction have not been executed in this packaging environment.**

The shared pair summarizer can then be used:

```bash
python scripts/summarize_pairs.py \
  --predictions Results/FiCoVuL/pairvul_top10_ficovul_pilot5/predictions.csv \
  --out-dir Results/comparisons/pairvul_top10_ficovul_pilot5/FiCoVuL
```

## Experimental protections

- No `train()` calls in the paired inference adapter; a missing checkpoint is a hard error.
- No random train/test splits created from the evaluation pairs.
- No vocabulary is learned, extended or repaired using test samples. Unknown node types fail explicitly; unknown lexical/value tokens require the **existing** training `<UNK>` vocabulary entry.
- No node vulnerability annotations are invented from function-level labels. Node-level localization accuracy is **not** reported.
- A checkpoint architecture is chosen from actual parameter keys; `load_state_dict(..., strict=True)` is mandatory.
- Each original `sample_id`, `pair_id`, `version`, and label is preserved and validated; incomplete or failed pairs affect reported coverage.
- Upstream source and configuration preserved; the additional adapter is isolated under `scripts/`.

## Documentation

- `docs/REPLICATION.md` — exact staged workflow and graph conversion prerequisites
- `docs/TRAINING.md` — retaining original training and planning leakage-safe retraining
- `docs/EXPERIMENT_PROTOCOL.md` — what Phase B should test, and what we cannot yet claim
- `docs/SOURCE_NOTES.md` — archive provenance, excluded binaries, licensing caveat
- `README_UPSTREAM.md` — original project documentation

### Licensing notice

The upstream README displays an MIT badge, but the supplied ZIP **did not contain a LICENSE file**. Verify the upstream license and third-party dependencies before distributing or publishing a modified repository. The large bundled legacy Joern `bin/` and `lib/` files were intentionally excluded; they are independent third-party executables and can be installed separately when needed.
