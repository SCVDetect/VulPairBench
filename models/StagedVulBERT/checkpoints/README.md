# Checkpoints (not included)

Place the published **BigVul fine-tuned FUNCTION-level** model at:

`checkpoints/function_level/model_2048.bin`

Alternatively use `scripts/run_pairvul.py --checkpoint /absolute/path/model_2048.bin`.

The paper's fine-grained **line-level** model is a different checkpoint; if needed store it under `checkpoints/line_level/`, along with the coarse model required by the line-level entry point. The **MSP pretraining** weights belong under `checkpoints/pretraining/`. Never treat pretrained MSP weights as a trained vulnerability classifier.

All checkpoints are deliberately omitted from this archive and ignored by Git. Keep hashes and provenance in experiment metadata.
