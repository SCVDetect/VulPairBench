# Milestone 01 — Restore, verify, and freeze original baselines

**Status:** repository structure prepared; GPU inference and checkpoint validation pending.

## Completion criteria

- [ ] Record the archive provenance and external references for LineVul, SCVdet, VVulDet.
- [ ] Run the six CPU-only repository tests and record the Git commit SHA.
- [ ] Restore model dependencies in separate environments. Record the exact versions rather than assuming a shared environment.
- [ ] Verify the checkpoint weights and architecture for **each** model; record file SHA-256, training dataset, random seed and model config (including tokenization / embeddings).
- [ ] Recover training/validation IDs, audit exact code/CVE overlap with official **PairVul test** samples, and document any unresolved overlap. Never describe contaminated results as unbiased held-out testing.
- [ ] Establish the official PairVul **586-pair test split**; treat the authors' larger JSON collections only as candidate data until split IDs are verified.
- [ ] Verify test input conversion on 2–10 paired functions: LineVul sequence length and patch truncation; VVulDet/SCVdet AST/PDG graph success; compare complete Joern CPG vs actual GNN graph.
- [ ] Run original checkpoints on the same paired input set; make sure both versions are inferred independently with weights frozen and no patch/CVE labels supplied as input features.
- [ ] Save individual model predictions in `Results/<model>/<run-id>/`, including stable IDs, vulnerable-class probability, failure/coverage metadata and reproducibility record.
- [ ] Run `scripts/standardize_predictions.py` and `scripts/summarize_pairs.py` and verify full pair completeness and model output semantics.

## Exit deliverables

1. Checkpoint provenance table, including unavailable/missing items.
2. Dataset partition and overlap audit (with strict test/development separation).
3. A model-by-model table of graph/token conversion success and coverage.
4. Pilot pair-accuracy outcome table (do not make claims from tiny pilot numbers).
5. A short research memo listing recurring security-relevant patch mechanisms to investigate with manual CPG/patch evidence.

**Do not start proposed-model development before Milestone 01 results are interpretable.** The first empirical research phase can begin with one clean checkpoint, but comparisons against multiple baselines require comparable held-out data and correctly adapted representations.
