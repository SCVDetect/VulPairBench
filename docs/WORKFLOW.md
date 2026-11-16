# Research protocol: paired vulnerable–patched code evaluation

**Primary claim to test:** do graph-based and sequence-based vulnerability detectors respond *appropriately* to security fixes, and can any failures be explained by missing/ignored security evidence?

## Phase A — dataset and training provenance (before models run)

- Establish the authors' actual **official 586-pair PairVul test manifest**, separately from the downloaded 2,740/4,314-pair source collections. Record checksums and the exact split. The JSON alone does not encode the official split.
- Review duplicates, identical code, purely non-functional changes, and reverted/superseded fixes; the original paper uses commit/patch-history verification not reproducible from these eight JSON fields alone. Do not claim the local preprocessing reproduces that validation.
- For **each checkpoint**, record training/validation file names, exact sample IDs, CVEs, function code fingerprints, seed, graph generation configuration, tokenizer, feature embeddings, preprocessing scripts, checkpoint SHA-256 and decision threshold. Check for exact and near-duplicate function overlap and shared CVEs between BigVul and PairVul.
- Separate a **development pair set** from the final held-out PairVul test. Do not inspect final test failures to develop the new model and then claim independent final confirmation.

## Phase B — original model inference

- Verify each checkpoint can load and reproduce at least one known baseline function with its original pipeline.
- Run independent inference on the `before` and `after` function without providing the opposite version, the patch, or the true label as an input feature.
- Record failed inputs, truncation, Joern errors, available context, and graph statistics. Check that the security-relevant patch lines are actually represented in the **model-consumed** graph, not just in the full Joern CPG.
- LineVul: token sequence length and patch truncation. VVulDet: CPG extraction, selected AST/PDG, domain knowledge provenance. SCVdet: function-level relationship context and graph construction. Do not silently simplify published architectures.
- Export a common `predictions.csv` with stable IDs and `status`, then evaluate only complete pairs for pair accuracy. Coverage belongs in the main table, not a footnote.

## Phase C — security-centered empirical study

For a representative sample of correct and incorrect pairs (sampling plan fixed without looking at the final outcomes where feasible), annotate:

1. CVE root cause and affected behavior (cite patch, upstream CVE documentation and project code).
2. Exact security-relevant code edits: changed guard, data flow, bounds check, resource lifetime or call target.
3. Evidence in full CPG: AST/CFG/CDG/DDG and any required environment/other functions.
4. Evidence in model input: which relevant nodes, statements, edges, and embeddings actually survive model preprocessing?
5. Prediction category: correct pair, both vulnerable (patched false positive), both benign (vulnerable false negative), or inverted.
6. Confidence in the annotation and whether the patch fully fixes the reported vulnerability. A code pair from a multi-function commit may not be independently causal.

Do **not** infer that a model used a graph feature simply because it appears in the CPG. Later controlled ablations or perturbations may help test causal dependence.

## Phase D — comparative and proposed-model experiments

- Share the same held-out test IDs, evaluation thresholds selected on validation data, and as much of the *training/validation partitions* as compatible architectures permit.
- Compare genuine function-level outputs and report separate full-pipeline vs reduced-context variants when necessary.
- Metrics: **pair accuracy**, before/after confusion categories, fraction of changing labels, score delta, standalone function precision/recall/F1/MCC, per-CWE results and graph/pipeline coverage.
- Report 95% CIs clustered at the **CVE level** because several function pairs can originate from one vulnerability; compare models using the same evaluable pairs. Repeat stochastic training runs and state the number of seeds.
- Isolate component effects using **matched ablations**: base model, +domain knowledge, +function context, +both, and controlled irrelevant or shuffled knowledge.
- Report preprocessing time, graph construction failure rate, training/inference cost, hardware and software versions.

## Data layout and output contract

- Raw PairVul JSONs stay in `datasets/raw/` (ignored).
- `scripts/prepare_pairvul.py` writes auditable candidate pairs and function-level input files to `datasets/processed/<name>/` (ignored). Any official selected test partition must be defined via a **separate explicit ID file**.
- Save per-model run artifacts under `Results/<model>/<run-id>/`, with metadata about environment and checkpoints. The adapter `scripts/standardize_predictions.py` joins by stable sample ID or audited mapping file.
- Analyze with `scripts/summarize_pairs.py`; it writes `summary.json` and `pair_outcomes.csv` into `Results/comparisons/<run-id>/<model>/`.
- After scientific and licensing review, version approved aggregate results separately; by default, experiment outputs are ignored to prevent accidental publication of large/unreviewed artifacts.

**Limitation:** No graph construction or GPU inference was run as part of this repository reorganization; model compatibility still requires validation on the restored server.
