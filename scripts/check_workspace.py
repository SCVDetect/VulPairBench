#!/usr/bin/env python3
"""Report readiness without importing GPU-dependent libraries."""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
for name in ('LineVul','SCVdet','VVulDet'):
    base=ROOT/'models'/name
    cp=base/'checkpoints'
    weights=[str(p.relative_to(ROOT)) for p in cp.rglob('*') if p.is_file() and p.suffix in ('.bin','.pt','.pth','.ckpt','.safetensors')]
    print(f'{name}: code={base.exists()}, local checkpoint candidates={len(weights)}, results={(ROOT/"Results"/name).exists()}')
    if weights:print(json.dumps(weights[:8],indent=2))
print('Note: checkpoint names, provenance and compatibility require manual verification. This script does not run inference.')
