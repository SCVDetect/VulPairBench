# Local benchmark data

Place data you are authorized to use in `raw/` (ignored by Git). Generated candidate manifests, function CSVs, and optional `.c` files go in `processed/<experiment>/` (also ignored). Explicit graph-ID mappings to stable `sample_id`s can be kept locally in `manifests/`.

The prepared code does not automatically identify the official PairVul test subset or exclude CVE overlap with model training sets. `scripts/prepare_pairvul.py` flags suspicious pairs without deleting any. Treat the outputs as an **audit**, not a ground-truth security validation.
