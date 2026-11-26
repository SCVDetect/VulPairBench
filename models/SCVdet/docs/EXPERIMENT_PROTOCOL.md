# PairVul SCVdet inference protocol

**Input**: the same `datasets/processed/pairvul_top10/samples.csv` as LineVul and StagedVulBERT. Strict version mapping: `before` → vulnerable (1); `after` → patched/assumed benign (0). All pairs are represented in the prepared manifest, and validation fails if one version is missing, duplicated or has an unexpected label. Input checks compare code SHA-256 hashes when available.

**Graph extraction**: each version is written to its own exact source text `.c` file under `storage/processed/<dataset-tag>/{before,after}/`. Joern is run directly on these files with the unchanged `get_func_graph.scala` script. The adapter checks the command exit code and the resulting node/edge JSON data. `joern_status.csv` contains per-sample status; failures are preserved.

**Graph representation**: `pdg+raw` via upstream `feature_extraction` with SCVdet's original graph orientation. Original CPG/PDG filtering and node-dropping are retained. The actual DGL representation is therefore not the full Joern CPG. Embedding is local CodeBERT; node features + function-level embedding; seeded random 100-D features; graph cache keyed by sample ID hash and version. `_LINE` is the original upstream Joern node-ID field, not a validated line number.

**Inference**: only checkpoint weights and stored trained function-context vector `v1`; model in evaluation mode, gradients disabled. The checkpoint is loaded strictly. A missing/unmatched checkpoint causes an error, never automatic retraining. The primary score is the softmax probability for class 1 of the function classification head, the primary predicted label is its argmax. Node-level aggregation is reported separately and not used for primary pair metrics.

**Metrics**: count successful graph predictions and full pairs separately. Report coverage, pair accuracy, label-change rate, outcome categories, and score deltas; incomplete pairs do not count as evaluable and their absence is visible in `prediction_failures.csv`. Compare with the shared `scripts/summarize_pairs.py` evaluator.

**Additional representation caution**: the CodeBERT embedder uses Hugging Face tokenizer `truncation=True` for its **function-level text embedding** (and individual node texts), even though the graph builder extracts code from a complete function. Therefore graph construction success does **not** imply that the function-level embedding observed the entire function. Audit graph structure and embedding token visibility separately in the eventual study.

**Reproducibility warnings**: no available DGL/Joern/checkpoint runtime was packaged for offline validation. Joern API and embeddings must be verified on the server. Differences from original training preprocessing, random-feature handling, `_LINE` metadata, checkpoint train-set overlap, graph-coverage selection, and risk of shared dataset leakage must be documented before making cross-model causal claims.
