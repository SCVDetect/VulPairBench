# FiCoVuL's role in the VulPairBench research design

## Phase A — Failure and security evidence (three models)

- LineVul: sequence/limited-token context.
- StagedVulBERT: hierarchical sequence/longer context.
- SCVdet: graph-based, function-relationship context.

Use the matched vulnerable/patched manifest, stable IDs, consistent labels, and paired metrics. Explain representational losses, checkpoint reproducibility, score shifts, and patch-level security mechanisms. These initial models are sufficient for a focused problem characterization; do not add FiCoVuL just to increase a baseline count.

## Phase B — Security-guided improvement

FiCoVuL is one possible independent graph architecture to test whether a curated, offline security knowledge intervention generalizes. It should be selected only after checkpoint/training reproduction, graph compatibility and representation audits. VVulDet can serve as an existing domain-aware reference but should not be confused with a knowledge-free control.

## Shared measurement contract

Each function-level prediction must include `sample_id`, `pair_id`, `version`, `true_label`, `pred_label`, `score_vulnerable`. Report (i) function-level classification, (ii) pair accuracy, (iii) before/after score delta, (iv) prediction-change direction, (v) graph extraction and model coverage, (vi) whether the actual security patch survived to the model's graph, and (vii) independently verified checkpoint behavior. Uncovered pairs count against coverage and do not enter conditional pair accuracy.

## Claims to avoid

- More code / larger graphs *caused* better/worse security discrimination without a controlled ablation.
- A checkpoint can be reconstructed from source files alone.
- A patch line not represented in a graph can nonetheless be interpreted as the model learning that fix.
- Paired-function labels automatically provide accurate node-level localization labels.
- Results on a repeatedly inspected 2,740-pair exploratory dataset prove held-out generalization.
