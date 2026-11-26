# Future model training and improvement notes

## Preserve the original baseline first

The upstream `FiCoVuL/FiCoVuL/train3.py` and `FiCoVuL/FiCoVuL/configs/config.json5` are retained unchanged. Original `train3.py` initializes `GATDualClassification`, has graph- and node-level training, loads `CroVul` by default, and saves state bundles with `state_dict`, the configuration and performance metadata. It uses `data/models/binaries/` and `data/models/checkpoints/` relative to its working directory, **not** the new `Results/` directory. Future training should use a dedicated run ID and a dedicated checkpoint output directory; do not overwrite original checkpoints.

From `models/FiCoVuL/FiCoVuL` you may inspect the upstream CLI:

```bash
python train3.py --help
```

**Do not launch full training with the default config until you've inspected it.** It targets an original CroVul dataset, may depend on upstream vocab/preprocessed graph assets, and contains environment-specific paths.

## Why we cannot train directly on PairVul yet

Paired data provides function labels (vulnerable before, patched after), but not reliable per-node vulnerable/non-vulnerable localization labels. FiCoVuL's dual training objective uses node-level evidence (`rpst_nodes`). Assigning all before nodes positive and all after nodes negative would create fabricated localization labels. The new adapter therefore assigns no node-level labels and performs graph-level inference only.

## Controlled improvement phase

1. Obtain a reproducible clean graph dataset with original node-localization annotations, or design and document an explicit *function-only* training ablation with a modified objective. Do not silently reuse the dual loss when node annotations are missing.
2. Split by CVE, repository, and code similarity before any training/validation feature creation. Keep both sides of each pair in the same partition. Audit BigVul/PairVul overlap.
3. Freeze an untouched final test set. Collect curated CWE/CVE or security mechanism knowledge **only** from permitted training sources; avoid test patches, test CVEs and future-commit leakage.
4. Train domain-agnostic FiCoVuL under matched budget/architecture/data, then compare a security-guided variant with controlled ablations: knowledge source, selected graph edges, evidence quality, extra parameters and inference cost.
5. Reproduce on at least one additional GNN if possible, with CVE-clustered uncertainty intervals and graph-coverage reporting.
6. Save model weights and vocabularies, graph/Joern version, hashes, split manifest, random seeds and frozen config for each run.

## Checkpoint structure

Recommended paths (ignored by Git):

```text
models/FiCoVuL/checkpoints/function_level/<run_id>.pth
models/FiCoVuL/checkpoints/vocab/<trained-run-specific-map-files>
```

In controlled retraining, use a **per-run vocabulary directory**, not a shared mutable `vocab/` folder. The `scripts/run_pairvul.py` adapter supports `--vocab-dir` for this purpose.

## Original configuration preservation

The original JSON5 configuration is preserved verbatim. For training experiments create named copies and document any differences, rather than editing the original and losing provenance. Separate graph-level improvements from node-label-based localization claims.
