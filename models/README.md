# Included baseline implementations

| Model | Family | Location | Primary function-level entry point |
|---|---|---|---|
| LineVul | Transformer / token sequence | `LineVul/` | `linevul/linevul_main.py` (`--do_test`) |
| SCVdet | GNN with function relationships | `SCVdet/` | `sourcescripts/model/scvuldetect.py` |
| VVulDet | Domain-aware GNN | `VVulDet/` | `sourcescripts/train_test.py` |

These are **distinct implementations with independent environments and data pipelines**, not components of a single Python package. The top-level repository provides output routing and evaluation tools; it does not merge their networks, labels or graph features. Look at `docs/MODEL_SETUP.md` before execution.

The supplied sources contained one LICENSE under LineVul; there is no license file for SCVdet or VVulDet. Check each source's publication and permission terms before public redistribution.
