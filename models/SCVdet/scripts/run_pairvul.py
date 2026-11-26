#!/usr/bin/env python3
"""Inference-only, version-aware SCVdet pipeline for VulPairBench.

Designed to run from the VulPairBench root with the existing SCVdet venv.
Original model architecture and its legacy training entry point are preserved.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime, timezone
from collections import Counter

SCVDET = Path(__file__).resolve().parents[1]
WORKSPACE = SCVDET.parents[1]
SRC = SCVDET / "sourcescripts"
STORAGE = SRC / "storage"
DEFAULT_SAMPLES = WORKSPACE / "datasets/processed/pairvul_top10/samples.csv"
PIPELINE_VERSION = "scvdet-pair-v1"
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
FIELDS = ("sample_id", "pair_id", "version", "label", "processed_func")


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as src:
        for block in iter(lambda: src.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def validate_tag(value: str, label: str):
    if not ID_RE.fullmatch(value) or value in (".", ".."):
        raise ValueError(f"Invalid {label}: {value!r} (allowed: letters, digits, dot, underscore, dash)")
    return value


def read_csv(path: Path):
    if not path.is_file():
        raise FileNotFoundError(f"Missing CSV: {path}")
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows, fields):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def normalize_samples(path: Path, limit_pairs: int | None = None):
    rows = read_csv(path)
    if not rows:
        raise ValueError("Input samples.csv is empty")
    if not set(FIELDS).issubset(rows[0]):
        raise ValueError(f"Input missing columns: {sorted(set(FIELDS) - set(rows[0]))}")
    bypair = {}
    seen = set()
    for row in rows:
        sid = row["sample_id"]
        pid = row["pair_id"]
        if not sid or not pid or sid in seen:
            raise ValueError(f"Empty/duplicate sample or pair ID: {sid!r} / {pid!r}")
        seen.add(sid)
        version = row["version"]
        if version not in ("before", "after"):
            raise ValueError(f"Invalid version: {sid} {version}")
        expected = "1" if version == "before" else "0"
        if str(row["label"]).strip() != expected:
            raise ValueError(f"Unexpected label: {sid}; expected {expected}")
        code = row["processed_func"]
        if not code.strip():
            raise ValueError(f"Empty code: {sid}")
        if row.get("source_sha256") and digest(code) != row["source_sha256"]:
            raise ValueError(f"Code SHA-256 differs from manifest for {sid}")
        if version in bypair.setdefault(pid, {}):
            raise ValueError(f"Duplicate {version} version for pair {pid}")
        bypair[pid][version] = row
    for pid, group in bypair.items():
        if len(group) != 2:
            raise ValueError(f"Incomplete/duplicate before-after pair: {pid}")
    # Consistent order by pair in input; always before then after.
    pairs = list(bypair.items())
    if limit_pairs is not None:
        if limit_pairs <= 0:
            raise ValueError("--limit-pairs must be positive")
        pairs = pairs[:limit_pairs]
    flat = []
    for pid, group in pairs:
        for version in ("before", "after"):
            row = group[version]
            # SHA avoids trusting arbitrary IDs as filesystem paths; mapping remains in manifest.
            key = "p" + hashlib.sha256(pid.encode()).hexdigest()[:20] + "__" + version
            flat.append({
                "sample_id": row["sample_id"], "pair_id": pid,
                "version": version, "label": int(row["label"]),
                "graph_id": key, "source_sha256": digest(row["processed_func"]),
                "cve_id": row.get("cve_id", ""),
                "code": row["processed_func"],
            })
    return flat


def paths(opts):
    tag = validate_tag(opts.dataset_tag, "dataset-tag")
    run = validate_tag(opts.run_id, "run-id")
    processed = STORAGE / "processed" / tag
    graph_dir = STORAGE / "cache/Graph" / f"{tag}_svuldet_codebert_pdg+raw"
    result_dir = WORKSPACE / "Results/SCVdet" / run
    return processed, graph_dir, result_dir


def prepared_manifest_path(processed):
    return processed / "sample_manifest.csv"


def prepare(opts, inputs):
    processed, graph_dir, result_dir = paths(opts)
    target = prepared_manifest_path(processed)
    fingerprint = digest("\n".join(f"{r['sample_id']}\t{r['source_sha256']}" for r in inputs))
    signature = processed / "source_manifest.json"
    if signature.exists():
        previous = json.loads(signature.read_text(encoding="utf-8"))
        if previous.get("fingerprint") != fingerprint and not opts.rebuild:
            raise RuntimeError(f"Dataset tag {opts.dataset_tag} has a different manifest; use a new --dataset-tag (preferred), or --rebuild")
    records = []
    for r in inputs:
        cpath = processed / r["version"] / f"{r['graph_id']}.c"
        cpath.parent.mkdir(parents=True, exist_ok=True)
        if not cpath.exists() or digest(cpath.read_text(encoding="utf-8")) != r["source_sha256"]:
            if cpath.exists() and not opts.rebuild:
                raise RuntimeError(f"Source file differs: {cpath} (use --rebuild)")
            cpath.write_text(r["code"], encoding="utf-8")
        records.append({k: r[k] for k in ("sample_id", "pair_id", "version", "label", "graph_id", "source_sha256", "cve_id")}
                       | {"source_file": str(cpath)})
    write_csv(target, records, list(records[0]))
    write_json(signature, {"fingerprint": fingerprint, "source_csv": str(Path(opts.samples).resolve()),
                           "dataset_tag": opts.dataset_tag, "samples": len(records), "utc": now()})
    print(f"Prepared {len(records)} original-code files: {processed}")
    return records


def existing_manifest(opts):
    processed, _, _ = paths(opts)
    p = prepared_manifest_path(processed)
    rows = read_csv(p)
    if not rows:
        raise ValueError(f"Empty prepared manifest: {p}")
    return rows


def joern_binary(opts):
    candidate = Path(opts.joern).expanduser() if opts.joern else STORAGE / "external/joern-cli/joern"
    if not candidate.is_file():
        raise FileNotFoundError(f"Joern executable not found: {candidate}")
    return candidate.resolve()


def validate_joern(source: Path):
    nodes = Path(str(source) + ".nodes.json")
    edges = Path(str(source) + ".edges.json")
    if not nodes.is_file() or not edges.is_file():
        raise FileNotFoundError(f"Joern output missing for {source}")
    n, e = json.loads(nodes.read_text(encoding="utf-8")), json.loads(edges.read_text(encoding="utf-8"))
    if not isinstance(n, list) or not isinstance(e, list) or not n:
        raise ValueError(f"Invalid/empty Joern graph for {source}")
    return len(n), len(e)


def extract(opts, records):
    script = STORAGE / "external/get_func_graph.scala"
    if not script.is_file():
        raise FileNotFoundError(f"Missing Joern Scala script: {script}")
    binary = joern_binary(opts)
    statuses = []
    for ix, r in enumerate(records, 1):
        source = Path(r["source_file"])
        status = {k: r[k] for k in ("sample_id", "pair_id", "version", "graph_id")}
        try:
            if not opts.rebuild:
                try:
                    nc, ec = validate_joern(source)
                    status.update(status="cached", joern_nodes=nc, joern_edges=ec, error="")
                    statuses.append(status)
                    continue
                except (FileNotFoundError, ValueError, json.JSONDecodeError):
                    pass
            # Avoid treating stale outputs as a successful fresh run.
            for ending in (".nodes.json", ".edges.json"):
                Path(str(source) + ending).unlink(missing_ok=True)
            command = [str(binary), "--script", str(script), "--param", f"filename={source}"]
            proc = subprocess.run(command, cwd=str(STORAGE / "external"), capture_output=True,
                                  text=True, timeout=opts.joern_timeout, check=False)
            if proc.returncode != 0:
                raise RuntimeError(f"Joern exit={proc.returncode}: {(proc.stderr or proc.stdout)[-1200:]}")
            nc, ec = validate_joern(source)
            status.update(status="ok", joern_nodes=nc, joern_edges=ec, error="")
        except Exception as exc:
            status.update(status="failed", joern_nodes=0, joern_edges=0, error=f"{type(exc).__name__}: {exc}")
        statuses.append(status)
        if ix % 50 == 0 or status["status"] == "failed":
            print(f"Joern [{ix}/{len(records)}] {r['graph_id']}: {status['status']}")
    _, _, result_dir = paths(opts)
    write_csv(result_dir / "joern_status.csv", statuses, list(statuses[0]))
    print("Joern status:", dict(Counter(x["status"] for x in statuses)))
    if opts.strict and any(x["status"] == "failed" for x in statuses):
        raise RuntimeError("Joern failures; see joern_status.csv")
    return statuses


def add_legacy_imports():
    for path in (str(SRC), str(SRC / "processing"), str(SRC / "model")):
        if path not in sys.path:
            sys.path.insert(0, path)


def find_codebert(opts):
    candidate = Path(opts.codebert_path).expanduser() if opts.codebert_path else STORAGE / "cache/embedmodel/CodeBERT"
    candidates = [candidate]
    if not opts.codebert_path:
        candidates += [STORAGE / "cache/embedmodel", STORAGE / "cache/embedmodel/Codebert",
                       STORAGE / "cache/embedmodel/codebert"]
    for candidate in candidates:
        if candidate.is_dir() and (candidate / "config.json").is_file():
            return candidate.resolve()
    raise FileNotFoundError(f"Cannot find local CodeBERT assets in {candidates}; use --codebert-path with a local Hugging Face model directory")


def graph_path(graph_dir, record):
    return graph_dir / record["graph_id"]


def build(opts, records):
    # Heavy imports deliberately deferred; --stage prepare and CLI help work without CUDA/DGL.
    add_legacy_imports()
    import torch
    import dgl
    from processing.dataprocessing import feature_extraction
    from embeddmodel.codebert import CodeBertEmbedder

    codebert_dir = find_codebert(opts)
    emb = CodeBertEmbedder(str(codebert_dir))
    emb.model.eval()
    _, graph_dir, result_dir = paths(opts)
    graph_dir.mkdir(parents=True, exist_ok=True)
    statuses = []
    for ix, r in enumerate(records, 1):
        output = graph_path(graph_dir, r)
        meta = Path(str(output) + ".meta.json")
        row = {k: r[k] for k in ("sample_id", "pair_id", "version", "graph_id")}
        try:
            if output.exists() and meta.exists() and not opts.rebuild:
                old = json.loads(meta.read_text(encoding="utf-8"))
                if old.get("source_sha256") != r["source_sha256"] or old.get("pipeline_version") != PIPELINE_VERSION:
                    raise RuntimeError("Stale graph cache; use --rebuild or a new --dataset-tag")
                loaded = dgl.load_graphs(str(output))[0][0]
                row.update(status="cached", nodes=loaded.num_nodes(), edges=loaded.num_edges(), error="")
                statuses.append(row)
                continue
            source = Path(r["source_file"])
            validate_joern(source)
            code, legacy_line_ids, ei, eo, et = feature_extraction(str(source), "pdg+raw")
            if not code or not ei or len(ei) != len(eo) or len(et) != len(ei):
                raise ValueError("No usable PDG graph or inconsistent extracted edges")
            n = len(code)
            if any(int(x) < 0 or int(x) >= n for x in (ei + eo)):
                raise ValueError("Graph edges reference invalid node indices")
            # Preserve original graph orientation, embeddings and random-feature distribution.
            g = dgl.graph((eo, ei), num_nodes=n)
            codes = [str(c).replace("\\t", "").replace("\\n", "") for c in code]
            features = []
            for start in range(0, len(codes), opts.embed_batch_size):
                features.append(emb.embed(codes[start:start + opts.embed_batch_size]).detach().cpu())
            g.ndata["_CODEBERT"] = torch.cat(features, dim=0).float()
            function_code = source.read_text(encoding="utf-8")
            func_emb = emb.embed(["</s> " + function_code]).detach().cpu()
            g.ndata["_FUNC_EMB"] = func_emb.repeat((n, 1)).float()
            # `_LINE` is actually upstream Joern node ID, not source lineNumber; preserve original feature layout.
            g.ndata["_LINE"] = torch.tensor([int(x) for x in legacy_line_ids], dtype=torch.int32)
            # No pair-derived line supervision. These labels are NEVER read by the forward pass.
            g.ndata["_VULN"] = torch.zeros(n, dtype=torch.float32)
            g.ndata["_FVULN"] = torch.zeros(n, dtype=torch.float32)
            # Upstream uses random 100-D node vectors; seed by graph ID to make caching reproducible.
            rng = torch.Generator(device="cpu").manual_seed(int(hashlib.sha256(r["graph_id"].encode()).hexdigest()[:15], 16))
            g.ndata["_RANDFEAT"] = torch.rand((n, 100), generator=rng)
            g.edata["_ETYPE"] = torch.tensor(et, dtype=torch.long)
            g = dgl.add_self_loop(g)
            dgl.save_graphs(str(output), [g])
            write_json(meta, {"pipeline_version": PIPELINE_VERSION, "source_sha256": r["source_sha256"],
                              "graph_id": r["graph_id"], "codebert": str(codebert_dir),
                              "nodes": g.num_nodes(), "edges": g.num_edges(), "utc": now()})
            row.update(status="ok", nodes=g.num_nodes(), edges=g.num_edges(), error="")
        except Exception as exc:
            row.update(status="failed", nodes=0, edges=0, error=f"{type(exc).__name__}: {exc}")
        statuses.append(row)
        if ix % 50 == 0 or row["status"] == "failed":
            print(f"Graph build [{ix}/{len(records)}] {r['graph_id']}: {row['status']}")
    write_csv(result_dir / "graph_status.csv", statuses, list(statuses[0]))
    print("Graph status:", dict(Counter(x["status"] for x in statuses)))
    if opts.strict and any(x["status"] == "failed" for x in statuses):
        raise RuntimeError("Graph build failures; see graph_status.csv")
    return statuses


def load_checkpoint(opts):
    add_legacy_imports()
    import torch
    from model.scvuldetect import LitSvulDetGAT

    path = Path(opts.checkpoint).expanduser() if opts.checkpoint else SCVDET / "checkpoints/best_model.ckpt"
    if not path.is_file():
        raise FileNotFoundError(f"Checkpoint not found: {path}. Inference never starts training automatically.")
    # Load only user-trusted checkpoints. PyTorch checkpoints can contain executable pickle objects.
    payload = torch.load(str(path), map_location="cpu", weights_only=False)
    if not isinstance(payload, dict):
        raise ValueError("Unexpected checkpoint format")
    state = payload.get("state_dict", payload)
    hparams = payload.get("hyper_parameters", {})
    config = hparams.get("config")
    cfg_source = "checkpoint hyper_parameters.config"
    if not config:
        config_file = Path(opts.config).expanduser() if opts.config else SCVDET / "checkpoints/best_confir.json"
        if not config_file.is_file():
            raise FileNotFoundError(f"Checkpoint lacks saved config and {config_file} is missing")
        config = json.loads(config_file.read_text(encoding="utf-8"))
        cfg_source = str(config_file)
    v1 = hparams.get("v1")
    if v1 is None:
        v1 = state.get("model.v1")
    if v1 is None:
        raise ValueError("Checkpoint missing trained v1; refusing to recalculate from test data")
    model = LitSvulDetGAT(config=config, v1=v1, pos_weight=hparams.get("pos_weight"))
    model.load_state_dict(state, strict=True)
    model.eval()
    # Reproduce original graph configuration only, never adapt weights or thresholds to test samples.
    if config.get("embedd_method") != "Codebert":
        raise ValueError(f"Checkpoint embedding method {config.get('embedd_method')} unsupported by paired adapter (Codebert only)")
    return model, path, config, cfg_source


def evaluate(opts, records):
    import torch
    import dgl
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    model, checkpoint, config, config_source = load_checkpoint(opts)
    _, graph_dir, result_dir = paths(opts)
    device = torch.device(opts.device if opts.device != "auto" else ("cuda:0" if torch.cuda.is_available() else "cpu"))
    model.to(device)
    predictions = []
    missing = []
    for ix, r in enumerate(records, 1):
        path = graph_path(graph_dir, r)
        if not path.exists():
            missing.append({k: r[k] for k in ("sample_id", "pair_id", "version", "graph_id")} | {"reason": "graph_file_missing"})
            continue
        try:
            meta_path = Path(str(path) + ".meta.json")
            if not meta_path.is_file():
                raise RuntimeError("Missing graph provenance file; rebuild paired graph cache")
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if meta.get("source_sha256") != r["source_sha256"] or meta.get("pipeline_version") != PIPELINE_VERSION:
                raise RuntimeError("Graph provenance mismatch: different code or pipeline; rebuild cache")
            g = dgl.load_graphs(str(path))[0][0]
            with torch.inference_mode():
                node_logits, func_logits = model(g.to(device))
                probs = torch.softmax(func_logits.reshape(-1, 2), dim=1)
                score = probs[0, 1].item()
                pred = int(probs[0].argmax().item())
                nprobs = torch.softmax(node_logits, dim=1)[:, 1]
                node_pred = int((nprobs > opts.threshold).any().item())
                node_ratio = float((nprobs > opts.threshold).float().mean().item())
            predictions.append({"sample_id": r["sample_id"], "function_id": r["sample_id"],
                                "graph_id": r["graph_id"], "pair_id": r["pair_id"], "version": r["version"],
                                "true_label": int(r["label"]), "label": int(r["label"]),
                                "pred_label": pred, "func_level_pred": pred,
                                "score_vulnerable": score, "node_aggregate_pred": node_pred,
                                "vulnerable_nodes_ratio": node_ratio,
                                "nodes": g.num_nodes(), "edges": g.num_edges()})
        except Exception as exc:
            missing.append({k: r[k] for k in ("sample_id", "pair_id", "version", "graph_id")} |
                           {"reason": f"{type(exc).__name__}: {exc}"})
        if ix % 100 == 0:
            print(f"Inference [{ix}/{len(records)}] predicted={len(predictions)} failed={len(missing)}")
    pred_fields = ["sample_id", "function_id", "graph_id", "pair_id", "version", "true_label", "label", "pred_label", "func_level_pred", "score_vulnerable", "node_aggregate_pred", "vulnerable_nodes_ratio", "nodes", "edges"]
    write_csv(result_dir / "predictions.csv", predictions, pred_fields)
    write_csv(result_dir / "raw_preds.csv", predictions, pred_fields)
    write_csv(result_dir / "function_level_predictions.csv", predictions, pred_fields)
    write_csv(result_dir / "prediction_failures.csv", missing, ["sample_id", "pair_id", "version", "graph_id", "reason"])
    metrics = paired_metrics(records, predictions)
    if predictions:
        truth = [p["true_label"] for p in predictions]
        labels = [p["pred_label"] for p in predictions]
        metrics["function_accuracy"] = accuracy_score(truth, labels)
        metrics["function_precision"] = precision_score(truth, labels, zero_division=0)
        metrics["function_recall"] = recall_score(truth, labels, zero_division=0)
        metrics["function_f1"] = f1_score(truth, labels, zero_division=0)
    checkpoint_sha256 = file_sha256(checkpoint)
    metrics.update({"checkpoint": str(checkpoint), "checkpoint_sha256": checkpoint_sha256,
                    "checkpoint_config_source": config_source,
                    "checkpoint_config": config, "device": str(device), "utc_finished": now(),
                    "note": "Graph logits (func_level_pred), NOT node aggregation. No test-time training; incomplete pairs excluded from pair accuracy and reported as uncovered."})
    write_json(result_dir / "metrics.json", metrics)
    write_json(result_dir / "run_metadata.json", {"model": "SCVdet", "dataset_tag": opts.dataset_tag, "run_id": opts.run_id,
                       "samples": str(opts.samples), "checkpoint": str(checkpoint), "checkpoint_sha256": checkpoint_sha256,
                       "config_source": config_source,
                       "utc_finished": now(), "pipeline_version": PIPELINE_VERSION, "model_config": config})
    print(json.dumps({k: v for k, v in metrics.items() if k not in ("checkpoint_config",)}, indent=2, default=str))
    if opts.strict and missing:
        raise RuntimeError("Missing/failed predictions; see prediction_failures.csv")
    return metrics


def paired_metrics(records, predictions):
    expected = {}
    for r in records:
        expected.setdefault(r["pair_id"], {})[r["version"]] = r["sample_id"]
    outputs = {p["sample_id"]: p for p in predictions}
    outcomes = Counter()
    score_deltas = []
    for pid, pair in expected.items():
        if not all(sid in outputs for sid in pair.values()):
            continue
        before = outputs[pair["before"]]
        after = outputs[pair["after"]]
        b, a = int(before["pred_label"]), int(after["pred_label"])
        category = {(0, 0): "both_benign", (1, 1): "both_vulnerable", (1, 0): "correct_pair", (0, 1): "inverted"}[(b, a)]
        outcomes[category] += 1
        score_deltas.append(before["score_vulnerable"] - after["score_vulnerable"])
    n = sum(outcomes.values())
    return {"expected_samples": len(records), "predicted_samples": len(predictions),
            "sample_coverage": len(predictions) / len(records) if records else 0,
            "total_pairs": len(expected), "evaluable_pairs": n,
            "pair_coverage": n / len(expected) if expected else 0,
            "pair_accuracy": outcomes["correct_pair"] / n if n else None,
            "label_change_rate": (outcomes["correct_pair"] + outcomes["inverted"]) / n if n else None,
            "outcomes": dict(outcomes), "mean_score_drop": sum(score_deltas) / n if n else None}


def show_preflight(opts):
    processed, graph_dir, result_dir = paths(opts)
    ckpt = Path(opts.checkpoint).expanduser() if opts.checkpoint else SCVDET / "checkpoints/best_model.ckpt"
    joern = Path(opts.joern).expanduser() if opts.joern else STORAGE / "external/joern-cli/joern"
    try:
        codebert = str(find_codebert(opts))
        codebert_ok = True
    except FileNotFoundError:
        codebert = str(opts.codebert_path or STORAGE / "cache/embedmodel/CodeBERT")
        codebert_ok = False
    print(json.dumps({"workspace": str(WORKSPACE), "input": str(Path(opts.samples).resolve()),
        "input_exists": Path(opts.samples).is_file(), "checkpoint": str(ckpt),
        "checkpoint_exists": ckpt.is_file(), "codebert": codebert, "codebert_exists": codebert_ok,
        "joern": str(joern), "joern_exists": joern.is_file(),
        "dataset_tag": opts.dataset_tag, "processed": str(processed), "graph_cache": str(graph_dir),
        "results": str(result_dir), "stage": opts.stage}, indent=2))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stage", choices=("prepare", "extract", "build", "predict", "all", "check"), default="all")
    ap.add_argument("--samples", type=Path, default=DEFAULT_SAMPLES)
    ap.add_argument("--dataset-tag", default="pairvul_top10")
    ap.add_argument("--run-id", default="pairvul_top10_scvdet_01")
    ap.add_argument("--checkpoint", type=Path, default=None)
    ap.add_argument("--config", type=Path, default=None, help="Fallback JSON config if checkpoint does not save config")
    ap.add_argument("--codebert-path", type=Path, default=None)
    ap.add_argument("--joern", type=Path, default=None)
    ap.add_argument("--device", default="auto", help="auto, cpu, cuda:0, etc")
    ap.add_argument("--limit-pairs", type=int, default=None, help="Use first N complete pairs (choose a separate dataset tag for a pilot)")
    ap.add_argument("--embed-batch-size", type=int, default=8)
    ap.add_argument("--threshold", type=float, default=0.5, help="Node aggregation only; function prediction is argmax graph logits")
    ap.add_argument("--joern-timeout", type=int, default=600)
    ap.add_argument("--rebuild", action="store_true", help="Regenerate source and graph files; does not delete cached files")
    ap.add_argument("--strict", action="store_true", help="Fail if any graph or inference sample fails")
    args = ap.parse_args(argv)
    paths(args)
    if args.embed_batch_size < 1 or not 0 <= args.threshold <= 1:
        ap.error("Invalid embedding batch size or threshold")
    if args.stage == "check":
        show_preflight(args)
        return 0
    if args.stage == "all":
        # Prevent costly Joern extraction when mandatory model assets are absent.
        find_codebert(args)
        joern_binary(args)
        required_ckpt = args.checkpoint or SCVDET / "checkpoints/best_model.ckpt"
        if not Path(required_ckpt).expanduser().is_file():
            raise FileNotFoundError(f"Missing SCVdet checkpoint: {required_ckpt}")
    # Independent stages resume from disk; the all stage composes them in order.
    if args.stage in ("prepare", "all"):
        inputs = normalize_samples(args.samples, args.limit_pairs)
        records = prepare(args, inputs)
    else:
        records = existing_manifest(args)
    if args.stage == "prepare":
        return 0
    _, _, result_dir = paths(args)
    result_dir.mkdir(parents=True, exist_ok=True)
    if args.stage in ("extract", "all"):
        extract(args, records)
    if args.stage in ("build", "all"):
        build(args, records)
    if args.stage in ("predict", "all"):
        evaluate(args, records)
    return 0


if __name__ == "__main__":
    sys.exit(main())
