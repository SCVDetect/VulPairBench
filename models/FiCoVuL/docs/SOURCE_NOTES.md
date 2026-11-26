# Supplied source provenance and modifications

- Supplied archive: `FiCoVuL-main.zip` (uploaded by user 2026-11-24); SHA-256 `48f40af12f61c09889923a9ed97624c35df9f24f8a38ca3c6cd37bbd8108ad02`.
- Archive root: `FiCoVuL-main/`.
- Original source directories `FiCoVuL/`, `Doxygen/`, original `requirements.txt`, `environment.yaml` and source `README.md` preserved (the README is renamed to `README_UPSTREAM.md`).
- `Doxygen/joern-cli/bin/` and `Doxygen/joern-cli/lib/` were excluded to avoid including ~74 MB of bundled, legacy third-party Joern binaries and Java archives. The original extraction scripts and Scala scripts remain. An upstream-compatible Joern installation must be supplied separately.
- A Finder `.DS_Store` file was excluded.
- New integration files are isolated under `scripts/`, `docs/`, `tests/`, with root `README.md` and updated root `.gitignore` (original preserved as `.gitignore_UPSTREAM`). The original model source, training code and `config.json5` were not modified.
- No `.pth` weights, training vocabularies or verified PairVul graph files were present in the supplied archive.
- Upstream README shows an MIT badge but the user-supplied archive contains no LICENSE text. Do not assume that a badge alone grants redistribution rights; confirm the upstream code license before public distribution.
- Run any `torch.load`/`pickle.load` only on checkpoints and maps from trusted sources, as these formats can execute arbitrary code.
