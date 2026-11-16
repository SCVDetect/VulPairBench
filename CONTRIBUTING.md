# Contributing to VulPairBench

Thank you for contributing. Our priorities are **research reproducibility, faithful baselines, and security-evidence quality**.

1. Work on a feature branch; explain whether a change affects **original model behavior** or only infrastructure. Avoid silent architecture/threshold/preprocessing changes.
2. Preserve author attribution and the original upstream READMEs/licenses. If importing an additional model, record its paper, repository link, commit hash, license, and environment requirements before merging.
3. Keep data, pretrained weights, local credentials, and experimental outputs untracked by default. Inspect `git status` and `git diff --cached --stat` before committing.
4. Run `python -m unittest discover -s tests -v` on proposed infrastructure changes. Add a CPU-only synthetic test for mapping, output schema or pair metric changes.
5. Use version-specific `sample_id` and shared `pair_id`. Never infer relationships from dataframe row order. Report failed graph construction and token truncation explicitly.
6. Do not contaminate a held-out test set by using its labels, CVE metadata or patch explanation in baseline inference or knowledge-generation training.
7. When diagnosing security behavior, support annotations with CVE/project/patch evidence; a prediction flip or a graph-node count is not proof of a valid fix or model comprehension.
8. Document hardware, software and configuration in each experiment. Save raw outputs in `Results/<model>/<run-id>/` and promote only vetted aggregate results for publication.

See `docs/MILESTONE_01.md` for the current agreed tasks.
