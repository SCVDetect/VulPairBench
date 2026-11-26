# Reproducibility and paired-code graph preprocessing

## Baseline / phase boundaries

The initial failure investigation uses the frozen checkpoints of LineVul, StagedVulBERT, and SCVdet. FiCoVuL is a prospective Phase B graph model for a *controlled* security-guided improvement (or independent generalization test). Do **not** portray it as an evaluated E04 baseline until the steps below actually pass.

## What the uploaded source establishes

The upstream includes `FiCoVuL/train3.py`, `FiCoVuL/test3.py`, `FiCoVuL/models/`, `FiCoVuL/dataset/`, `FiCoVuL/configs/config.json5`, and the `Doxygen/` graph extraction scripts. `train3.py` instantiates `GATDualClassification`; `test3.py` instantiates `GATBinaryClassification`. This distinction matters for checkpoint loading. Upstream testing creates aggregate metrics but has no stable paired-sample prediction exporter. The new `scripts/run_pairvul.py` detects the architecture from checkpoint keys and uses strict loading.

The source does **not** contain a trained `.pth` detector, the maps needed for its original embeddings, or a complete verified end-to-end standalone snippet extraction example.

## Stage 0 — Validate original reproduction

1. Create an isolated environment (use the upstream `environment.yaml` or `requirements.txt` as references, not as proof of a working modern environment). Run `python models/FiCoVuL/scripts/run_pairvul.py --stage check` from VulPairBench root.
2. Obtain a legally reusable original checkpoint **and the training-run vocabulary files**. A pretrained CodeBERT download is not a substitute for a trained FiCoVuL classifier.
3. Validate the checkpoint on its original graph/test dataset, using the corresponding original Joern and preprocessing configuration. Record original results, source commit, Python/PyTorch versions, Joern version, checkpoint hash, and vocabulary hashes. Do not proceed if loading only works with `strict=False` or the original benchmark is irreproducible.
4. Independently verify the intended Joern export schema and method selection on representative C/C++ samples, including preprocessor/macro cases.

## Stage 1 — Prepare original before/after code

```bash
python models/FiCoVuL/scripts/run_pairvul.py \
  --stage prepare \
  --samples datasets/processed/pairvul_top10/samples.csv \
  --dataset-tag pairvul_top10_pilot5 --limit-pairs 5
```

Outputs:

- `work/pairvul_top10_pilot5/manifest.csv` (source path, original sample/pair IDs, labels, SHA-256).
- `work/pairvul_top10_pilot5/source/before/*.c`
- `work/pairvul_top10_pilot5/source/after/*.c`
- `work/pairvul_top10_pilot5/prepare_report.json`

The code is copied **verbatim**; there is no comment removal, deduplication, relabeling, or train/test split.

## Stage 2 — Extract original FiCoVuL-compatible graphs (not automated yet)

The upstream extraction is not equivalent to pointing Joern at arbitrary `*.c` files. In particular, `Doxygen/run_joern.py` accepts only `CVE`, `SARD`, `WILD` and uses Doxygen-generated metadata; the upstream `extract_joern.py` expects an annotation `function_name` matching Joern's reported method name and produces one graph file per method.

After independently validating a suitable original-compatible Joern export method, provide a **separate graph JSON** for *each* sample at:

`work/<dataset-tag>/joern/<graph_id>.json`

The `graph_id` is given in the manifest and is unique for `before` and `after`. **Do not reuse the before graph for after.** Preserve a provenance log containing Joern version, command, return code, JSON hash, extraction warnings, selection of the target function, and parsing failures.

Required normalized JSON structure (based on the source `extract_joern.py`):

```json
{
  "properties": {"origin_path": "...", "function_name": "...", "class": [], "depth": 0, "label": 1, "lines": []},
  "nodes": {
    "0": {"id": "...", "type": "METHOD", "code": "...", "line": -1, "column": -1},
    "1": {"id": "...", "type": "METHOD_RETURN", "code": "RET", "line": -1, "column": -1}
  },
  "edges": [[0, 1, 0]]
}
```

This is a **schema illustration, not a genuine extracted graph**; no example here should be submitted as data. Node IDs must be contiguous `0..N-1`. Relation type IDs follow upstream `extract_joern.py`; the original loader retains only relation IDs `0,1,2,3`. The graph must have at least two nodes and at most 5,000 nodes, matching the source's preprocessing filter. The security meaning of retained edges must be audited: the upstream exporter may differ by Joern version.

## Stage 3 — Build model inputs with *training* vocabularies

```bash
python models/FiCoVuL/scripts/run_pairvul.py \
  --stage build --dataset-tag pairvul_top10_pilot5 \
  --checkpoint models/FiCoVuL/checkpoints/function_level/model.pth \
  --vocab-dir models/FiCoVuL/checkpoints/vocab --strict
```

Outputs: `work/<tag>/model_ready/test.json`, `graph_status.csv`, `build_report.json`.

The adapter applies the original `CodeNormalizer`, and reads the original `node_type_dict.pkl`, `word_lexical_dict.pkl`, `word_value_dict.pkl`, and `most_common_function_names.txt`. It **never** fits new maps to the benchmark. For future controlled retraining, generate vocabularies on *training data only* and freeze them before any evaluation.

The current feature adapter supports checkpoint preprocessing modes `RAW` and `RAW_WO_RENAME`. Other original modes must be implemented and validated separately. Any feature failures are recorded rather than replaced with blank graphs.

## Stage 4 — Frozen-checkpoint predictions

```bash
python models/FiCoVuL/scripts/run_pairvul.py \
  --stage predict --dataset-tag pairvul_top10_pilot5 \
  --run-id pairvul_top10_ficovul_pilot5 \
  --checkpoint models/FiCoVuL/checkpoints/function_level/model.pth \
  --vocab-dir models/FiCoVuL/checkpoints/vocab --device cpu --strict
```

Output: `Results/FiCoVuL/<run-id>/` (`predictions.csv`, `raw_preds.csv`, `prediction_failures.csv`, `metrics.json`, `run_metadata.json`). Use a unique run ID; do not overwrite runs. Test **original benchmark reproducibility first**, then begin with five paired functions, and only then use all 2,740 candidate pairs.

### Limitations of the integration

- Joern export of isolated kernel functions is **not automatically implemented or validated** by this ZIP. The user must generate verified compatible graphs.
- Neither a trained checkpoint nor checkpoint vocabularies were supplied; full inference is **not tested**.
- The model may require original, project-level caller/callee context; standalone extraction can change its representation. Report that difference.
- No test set should be used to choose vocabularies, graph pruning rules, model thresholds, or training hyperparameters.
- Graph classification is the paired-code metric. Node localization metrics are intentionally excluded without node-level ground truth.
