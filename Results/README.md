# Experimental Results

All generated model output files belong under `Results/<model>/<run-id>/`. This includes raw function/line predictions, vulnerability probabilities, metrics, and diagnostics. The root `.gitignore` excludes **all run directories and model-generated files**, while preserving this documentation and model-level README files.

Suggested convention: `<dataset>_<checkpoint>_<seed>_<protocol-version>` using only letters, digits, dot, dash and underscore. For example: `pairvul_ckptA_seed42_v1`.

Cross-model derived results go under `Results/comparisons/<run-id>/`. Check the `pair_id` mapping and complete-pair coverage before comparing. Results do **not** include checkpoint files or the raw vulnerability benchmark.
