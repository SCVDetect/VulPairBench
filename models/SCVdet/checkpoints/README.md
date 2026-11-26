# User-supplied checkpoints (Git ignored)

Place the trusted **original** SCVdet model checkpoint at `best_model.ckpt`. If the checkpoint does not include its model config in `hyper_parameters.config`, also provide the exact corresponding `best_confir.json` here. The learned function-relationship vector `v1` must already exist inside the checkpoint; the paired inference adapter will not compute it on the test set.

For future training choose a dedicated `SCVDET_CHECKPOINT_DIR` pointing to a **new folder** so the original checkpoint is never overwritten. Consult `../docs/TRAINING.md`.
