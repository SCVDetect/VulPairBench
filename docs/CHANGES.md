# Initial organization — 2026-11-16

## Preserved materials

- Moved the complete supplied `LineVul/`, `SCVdet/`, and `VVulDet/` folders into `models/`; preserved their original research READMEs, source code, model requirements, demonstration data and images. Removed `.DS_Store` platform metadata.
- Retained `LineVul/LICENSE`. The supplied archive contains no standalone license files for SCVdet or VVulDet; do not automatically apply LineVul licensing to their code.
- Retained supplied SCVdet `outputdata/` as historical example material. It is **not** a result of VulPairBench experiments.

## Targeted code modifications

1. `models/LineVul/linevul/linevul_main.py`: added configurable centralized result path, redirected raw predictions / PR plots / local explanation files; exported positive-class probability and original metadata, tolerated missing flaw-line metadata for function-level data. Original model computation is unchanged.
2. `models/SCVdet/sourcescripts/uutils/__utils__.py`: centralized result paths and checkpoint directory helper. `models/SCVdet/sourcescripts/model/` primary and legacy entry points: explicitly referenced checkpoint paths moved out of result artifacts; trial checkpoints placed in separate `trial_<n>/` folders to prevent overwriting each other and the selected best checkpoint. `scvuldetect.py` additionally exports positive-class function confidence.
3. `models/VVulDet/sourcescripts/utils/utills.py`: same output/checkpoint path separation. `train_test.py` now recovers checkpoint from `models/VVulDet/checkpoints/` and retains positive-class function probability in its prediction CSV.
4. New standard-library tools for manifest creation, format normalization by stable ID, paired outcome summaries, workspace checks, and guarded model launch.
5. Updated root `.gitignore` to prevent data, results, checkpoints, SSH keys and caches from being committed accidentally.

## Explicit non-goals / remaining checks

- Did not retrain models, generate new Joern graphs, download weights, recover datasets, or validate inference on GPU. No original checkpoint is bundled.
- No assertion that datasets, original author scripts, parser paths, or dependency versions will run unchanged on a modern server.
- Original SCVdet and VVulDet **may train automatically** if checkpoints are missing; the new wrapper prevents accidental training without opt-in.
- Existing model paths may be tied to the original experiment storage. Compare the actual config, Joern/CodeBERT versions and graph ID convention when restoring assets.
- `LineVul` and GNN prediction CSV formats differ; normalization requires manifest-aligned IDs. The GNN scripts do not natively know PairVul `sample_id`s without an explicit bridge from graph preprocessing.
- Security-oriented empirical analysis and the new domain-guided architecture are *future research activities*, not implemented here.
