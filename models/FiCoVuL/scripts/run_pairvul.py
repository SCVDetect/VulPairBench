#!/usr/bin/env python3
"""VulPairBench FiCoVuL integration. Upstream architectures remain unchanged.

Stages:
  check   -- inspect locally available requirements (no checkpoint load)
  prepare -- export paired original C functions and an ID-safe manifest
  build   -- encode upstream-format Joern JSON with TRAINING checkpoint vocabularies
  predict -- frozen-checkpoint graph-level prediction to Results/FiCoVuL/run-id

IMPORTANT: This script does not claim automatic Joern extraction. See docs/REPLICATION.md.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import importlib.util
import json
import math
import os
import pickle
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

MODEL = Path(__file__).resolve().parents[1]
REPO = MODEL.parents[1]
SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def atomic_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    tmp.replace(path)


def atomic_csv(path: Path, records: list[dict], columns: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
        w.writeheader(); w.writerows(records)
    tmp.replace(path)


def read_csv(path: Path):
    with path.open(newline='', encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))


def sha(data: bytes):
    return hashlib.sha256(data).hexdigest()


def work_dir(tag: str) -> Path:
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}', tag):
        raise ValueError('dataset-tag must be a short safe folder name')
    return MODEL / 'work' / tag


def result_dir(run_id: str) -> Path:
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}', run_id):
        raise ValueError('run-id must be a short safe folder name')
    return REPO / 'Results' / 'FiCoVuL' / run_id


def normalized_graph_id(sample_id: str):
    # Avoid path traversal and maintain stable identity; never drop pair/version labels.
    if SAFE.fullmatch(sample_id) and len(sample_id) <= 140 and sample_id not in ('.', '..'):
        return sample_id
    return 's' + sha(sample_id.encode('utf-8'))[:24]


def normalize_samples(rows):
    if not rows:
        raise ValueError('Input CSV has no samples')
    required = {'sample_id', 'pair_id', 'version'}
    if required - set(rows[0]):
        raise ValueError(f'Missing required CSV columns: {sorted(required-set(rows[0]))}')
    code_column = next((c for c in ('processed_func','code','function') if c in rows[0]), None)
    label_column = next((c for c in ('target','label') if c in rows[0]), None)
    if code_column is None or label_column is None:
        raise ValueError('Require processed_func/code/function and target/label columns')
    pair_groups = defaultdict(dict)
    seen_ids, seen_graphs = set(),set()
    for r in rows:
        sample_id, pair_id, version = (r[x] for x in ('sample_id','pair_id','version'))
        if not sample_id or not pair_id or version not in ('before', 'after'):
            raise ValueError('Each sample requires nonempty IDs and version before/after')
        if sample_id in seen_ids: raise ValueError(f'Duplicate sample_id: {sample_id}')
        seen_ids.add(sample_id)
        if version in pair_groups[pair_id]: raise ValueError(f'Duplicate version in pair: {pair_id}')
        try: label=int(r[label_column])
        except (ValueError,TypeError): raise ValueError(f'Invalid label for {sample_id}')
        if label != (1 if version == 'before' else 0):
            raise ValueError(f'Label/version mismatch in {sample_id}: {version} has label {label}')
        code=r[code_column]
        if not code or not code.strip(): raise ValueError(f'Empty code for {sample_id}')
        gid=normalized_graph_id(sample_id)
        if gid in seen_graphs: raise ValueError(f'Graph ID collision for {sample_id}')
        seen_graphs.add(gid)
        pair_groups[pair_id][version]={
            'sample_id':sample_id,'pair_id':pair_id,'version':version,
            'label':label,'graph_id':gid,'code':code,
            'code_sha256':sha(code.encode('utf-8'))}
    incomplete=[p for p,g in pair_groups.items() if set(g)!= {'before','after'}]
    if incomplete: raise ValueError(f'Incomplete pairs ({len(incomplete)}), e.g. {incomplete[:3]}')
    return pair_groups


def stage_prepare(args):
    samples=Path(args.samples).resolve()
    groups=normalize_samples(read_csv(samples))
    pairs=list(groups)
    if args.limit_pairs is not None:
        if args.limit_pairs <= 0: raise ValueError('limit-pairs must be positive')
        pairs=pairs[:args.limit_pairs]
    base=work_dir(args.dataset_tag)
    records=[]
    for pair in pairs:
        for ver in ('before','after'):
            r=dict(groups[pair][ver]); code=r.pop('code')
            src=base/'source'/ver/(r['graph_id']+'.c')
            src.parent.mkdir(parents=True,exist_ok=True)
            if src.exists() and sha(src.read_bytes()) != r['code_sha256'] and not args.overwrite:
                raise FileExistsError(f'Existing source differs; pass --overwrite: {src}')
            src.write_text(code,encoding='utf-8')
            r['source_file']=str(src.relative_to(base))
            records.append(r)
    cols=['sample_id','pair_id','version','label','graph_id','source_file','code_sha256']
    atomic_csv(base/'manifest.csv',records,cols)
    atomic_json(base/'prepare_report.json',{
        'source':str(samples),'source_sha256':sha(samples.read_bytes()),
        'pairs':len(pairs),'samples':len(records),'code_policy':'verbatim',
        'graph_extraction':'not run; see docs/REPLICATION.md',
        'created_utc':datetime.now(timezone.utc).isoformat()})
    print(f'Prepared {len(records)} code files ({len(pairs)} pairs): {base}')
    print('Next: generate model-compatible Joern JSON under work/<dataset-tag>/joern/<graph_id>.json.')


def manifest_records(tag):
    manifest=work_dir(tag)/'manifest.csv'
    if not manifest.exists(): raise FileNotFoundError(f'No manifest: {manifest}. Run --stage prepare.')
    data=read_csv(manifest)
    if not data: raise ValueError('Empty manifest')
    for r in data:
        if r['version'] not in ('before','after'): raise ValueError('Bad manifest version')
        if r['graph_id'] != normalized_graph_id(r['sample_id']): raise ValueError('Graph ID mismatch in manifest')
    return data


def stage_check(args):
    def yes(path):return str(Path(path).exists())
    deps={x: bool(importlib.util.find_spec(x)) for x in ('torch','numpy','json5','pygments','regex','ordered_set','gensim')}
    ckpt=Path(args.checkpoint) if args.checkpoint else MODEL/'checkpoints/function_level/model.pth'
    vocab=Path(args.vocab_dir) if args.vocab_dir else MODEL/'checkpoints/vocab'
    report={
       'model_root':str(MODEL),'repo_root':str(REPO),
       'original_config':yes(MODEL/'FiCoVuL/configs/config.json5'),
       'checkpoint_path':str(ckpt),'checkpoint_exists':ckpt.exists(),
       'vocab_dir':str(vocab),'vocab_files':{
          f: (vocab/f).exists() for f in ('node_type_dict.pkl','word_lexical_dict.pkl','word_value_dict.pkl','most_common_function_names.txt')},
       'python_dependencies_present':deps,
       'dataset_prepared':(work_dir(args.dataset_tag)/'manifest.csv').exists(),
       'upstream_joern_libraries_bundled':(MODEL/'Doxygen/joern-cli/lib').exists(),
       'note':'Full inference requires a trusted checkpoint, its original vocab, and graph JSON. No model inference performed.'}
    print(json.dumps(report, indent=2))


def map_index(vocab, token, unk=True):
    if token in vocab: return vocab.index(token)
    if unk and '<UNK>' in vocab:return vocab.index('<UNK>')
    raise ValueError(f'Value not present in TRAINING vocabulary: {token!r}')


def ensure_checkpoint_enum_import_compatibility():
    """Map training-time `dataset.*` import names to the package's canonical classes.

    Upstream train3.py imports `dataset.data_preprocess` when executed from its
    inner FiCoVuL directory, while the model package imports
    `FiCoVuL.dataset.data_preprocess`. Without this alias, pickled enums may
    be different Python classes, invalidating checkpoint configuration checks.
    Only use with trusted checkpoint files.
    """
    import FiCoVuL.dataset as dataset_pkg
    import FiCoVuL.dataset.data_preprocess as dataset_preprocess
    sys.modules.setdefault('dataset', dataset_pkg)
    sys.modules.setdefault('dataset.data_preprocess', dataset_preprocess)


def load_vocab_dir(vocab_dir):
    d=Path(vocab_dir)
    if not d.is_dir(): raise FileNotFoundError(f'Original training vocab directory not found: {d}')
    names=('node_type_dict.pkl','word_lexical_dict.pkl','word_value_dict.pkl')
    # Pickle and torch checkpoints must only come from trusted, verified sources.
    maps=[pickle.loads((d/n).read_bytes()) for n in names]
    common=(d/'most_common_function_names.txt')
    if not common.exists(): raise FileNotFoundError(f'Missing training function-name list: {common}')
    return (*maps,common.read_text(encoding='utf-8').splitlines())


def make_native_graph(data, code, label, maps, preprocess_method):
    from FiCoVuL.dataset.data_preprocess import CodeNormalizer
    types,lexicals,values,most_common=maps
    if preprocess_method not in ('RAW','RAW_WO_RENAME'):
        raise ValueError(f'Unsupported feature extraction method: {preprocess_method}; requires original method verification')
    cn=CodeNormalizer('cpp',code,most_common, rename=preprocess_method!='RAW_WO_RENAME')
    lines=code.split('\n')
    nodes=data.get('nodes'); edges=data.get('edges')
    if not isinstance(nodes,dict) or not isinstance(edges,list): raise ValueError('Graph requires nodes object and edges array')
    n=len(nodes)
    if n<2 or n>5000:raise ValueError(f'Graph node count outside original allowed range: {n}')
    expected=[str(i) for i in range(n)]
    if set(nodes)!=set(expected):raise ValueError('Graph IDs must be contiguous integers 0..N-1')
    sorted_nodes=[nodes[i] for i in expected]
    _type=[map_index(types,node['type'],unk=False) for node in sorted_nodes]
    lexical, val = [],[]
    for node in sorted_nodes:
        raw=node.get('code','')
        if not raw: a,b=[],[]
        elif node['type']=='METHOD_RETURN' and raw=='RET':a,b=['Token.Keyword'],['RET']
        else:
            line=int(node.get('line',-1));col=int(node.get('column',-1))
            if (line,col)==(-1,-1):
                if node['type']=='METHOD':a,b=['Token.Name.Function'],[cn.renamer.get(raw,raw)]
                elif node['type']=='LOCAL':a,b=['Token.Name'],[cn.renamer.get(raw,raw)]
                else:raise ValueError(f'Unlocated node {node["type"]}, {raw!r}')
            else:
                if line<1 or line>len(lines) or col<0:raise ValueError(f'Invalid line/column: {line}:{col}')
                start=sum(len(l)+1 for l in lines[:line-1])+col
                a,b=cn.localize_tokens(start,start+len(raw))
        lexical.append([map_index(lexicals,t) for t in a]);val.append([map_index(values,t) for t in b])
    safe_edges=[]
    for e in edges:
        if not isinstance(e,(list,tuple)) or len(e)<3:raise ValueError('Graph edge should be [source,target,relation]')
        x,y,t=[int(v) for v in e[:3]]
        if not(0<=x<n and 0<=y<n and 0<=t<=11):raise ValueError(f'Invalid edge: {e}')
        safe_edges.append([x,y,t])
    if not any(t in (0,1,2,3) for _,_,t in safe_edges):
        raise ValueError('No edges among original FiCoVuL selected relations 0–3')
    # No ground-truth node labels are available in the paired code benchmark.
    return {'node_types':_type,'node_lexical_features':lexical,
        'node_value_features':val,'edges':safe_edges,
        'rpst_nodes':{'0':[],'1':[]},'class':[], 'label':int(label)}


def stage_build(args):
    manifest=manifest_records(args.dataset_tag)
    if not args.checkpoint:raise ValueError('--stage build requires --checkpoint to verify preprocessing compatibility')
    # These imports only occur when the user chooses a model-dependent stage.
    import torch
    ckpt=Path(args.checkpoint).resolve()
    if not ckpt.exists(): raise FileNotFoundError(ckpt)
    ensure_checkpoint_enum_import_compatibility()
    checkpoint=torch.load(ckpt,map_location='cpu',weights_only=False)  # trusted checkpoint only
    method=checkpoint['preprocess']['method']
    method=getattr(method,'name',method)
    if method not in ('RAW','RAW_WO_RENAME'):
        raise ValueError(f'Only original RAW and RAW_WO_RENAME features are supported: {method}')
    maps=load_vocab_dir(args.vocab_dir)
    base=work_dir(args.dataset_tag)
    graph_dir=Path(args.graph_dir).resolve() if args.graph_dir else base/'joern'
    graphs={}; statuses=[]
    for r in manifest:
        gid=r['graph_id']; path=graph_dir/(gid+'.json')
        st={'sample_id':r['sample_id'],'pair_id':r['pair_id'],'version':r['version'],'graph_id':gid,
            'graph_path':str(path),'status':'failed','reason':''}
        try:
            if not path.is_file():raise FileNotFoundError('No matching Joern graph JSON')
            data=json.loads(path.read_text(encoding='utf-8'))
            code=(base/r['source_file']).read_text(encoding='utf-8')
            if sha(code.encode('utf-8'))!=r['code_sha256']:
                raise ValueError('Source modified since manifest was prepared')
            graph=make_native_graph(data,code,int(r['label']),maps,method)
            graphs[gid]=graph
            st['status']='ok'
        except Exception as e:
            st['reason']=f'{type(e).__name__}: {str(e)[:500]}'
        statuses.append(st)
    output=base/'model_ready'/'test.json'
    ordered=[r['graph_id'] for r in manifest if r['graph_id'] in graphs]
    atomic_json(output,{'n_graphs':len(ordered),'graph_id_index':ordered,'graphs':graphs})
    atomic_csv(base/'graph_status.csv',statuses,list(statuses[0]))
    count=Counter(s['status'] for s in statuses)
    atomic_json(base/'build_report.json',{
        'dataset_tag':args.dataset_tag,'checkpoint_sha256':sha(ckpt.read_bytes()),
        'checkpoint_preprocessing_method':method,
        'vocab_dir':str(Path(args.vocab_dir).resolve()),'graph_dir':str(graph_dir),
        'expected_samples':len(manifest),'ready_samples':len(graphs),'statuses':count,
        'note':'No node-localization labels; native graph-level input only.'})
    print(f'Built {len(graphs)}/{len(manifest)} model-ready graphs; status: {dict(count)}')
    if args.strict and len(graphs)!=len(manifest):
        raise RuntimeError('Graph coverage <100%; see work/<dataset-tag>/graph_status.csv')


def make_loader_item(graph, original_config):
    import torch
    from FiCoVuL.dataset.data_loader import GraphDataLoader, MINE_NUM_RELATIONS, MINE_RALATIONS_INDEX_MAP
    n=len(graph['node_types'])
    edges=[(int(x),int(y),MINE_RALATIONS_INDEX_MAP[int(t)]) for x,y,t in graph['edges'] if int(t) in MINE_RALATIONS_INDEX_MAP]
    if not edges: raise ValueError('No allowed graph edges')
    edge_idx=torch.tensor(edges,dtype=torch.long).T.contiguous()
    if original_config['model']['add_reverse_edge']:
        rev=edge_idx.index_select(0,torch.LongTensor([1,0,2])) + torch.tensor([[0],[0],[MINE_NUM_RELATIONS]])
        edge_idx=torch.cat([edge_idx,rev],dim=1)
    if original_config['model']['add_self_loop']:
        nodes_index=torch.tensor(list(range(n)),dtype=torch.long).repeat(1,MINE_NUM_RELATIONS)
        relations=torch.arange(MINE_NUM_RELATIONS,dtype=torch.long).view(1,-1).repeat_interleave(n,dim=1)
        edge_idx=torch.cat([edge_idx,torch.cat([nodes_index,nodes_index,relations],dim=0)],dim=1)
    features=[[torch.tensor(x,dtype=torch.long) for x in graph[key]] for key in
              ('node_types','node_lexical_features','node_value_features')]
    labels=torch.tensor([float(graph['label'])])
    rpst=torch.tensor([-1.0]*n)
    loader=GraphDataLoader([features],[labels],[edge_idx],[rpst],batch_size=1,shuffle=False)
    return next(iter(loader))


def stage_predict(args):
    ckpt=Path(args.checkpoint).resolve() if args.checkpoint else MODEL/'checkpoints/function_level/model.pth'
    if not ckpt.is_file():raise FileNotFoundError(f'Missing checkpoint: {ckpt}; no training fallback')
    import torch
    from FiCoVuL.dataset.data_loader import MINE_NUM_RELATIONS
    from FiCoVuL.models.GATClassification import GATBinaryClassification, GATDualClassification
    rdir=result_dir(args.run_id)
    if (rdir/'predictions.csv').exists() and not args.overwrite:
        raise FileExistsError(f'Predictions already exist in {rdir}; use new --run-id or --overwrite')
    rows=manifest_records(args.dataset_tag)
    base=work_dir(args.dataset_tag)
    model_graph_file=base/'model_ready'/'test.json'
    if not model_graph_file.exists(): raise FileNotFoundError(f'Model-ready graph file missing: {model_graph_file}')
    native=json.loads(model_graph_file.read_text())
    if set(native['graph_id_index'])!=set(native['graphs']) or native['n_graphs']!=len(native['graph_id_index']):
        raise ValueError('Invalid model-ready graph index')
    for r in rows:
        g=native['graphs'].get(r['graph_id'])
        if g and int(g['label'])!=int(r['label']):raise ValueError(f'Graph-label mismatch: {r["graph_id"]}')
    device=torch.device('cpu' if args.device=='cpu' else ('cuda' if args.device=='cuda' and torch.cuda.is_available() else 'cpu'))
    if args.device=='cuda' and device.type!='cuda':raise RuntimeError('CUDA requested but unavailable')
    ensure_checkpoint_enum_import_compatibility()
    state=torch.load(ckpt,map_location='cpu',weights_only=False)  # trusted files only
    if not isinstance(state,dict) or 'state_dict' not in state or 'model' not in state:
        raise ValueError('Unsupported checkpoint format; expected upstream training state')
    maps=load_vocab_dir(args.vocab_dir)
    type_map,lexical_map,word_map,_=maps
    cfg=state
    sd=state['state_dict']
    is_dual=any(k.startswith('gat_layers.') or k.startswith('node_classifier.') for k in sd)
    is_binary=any(k.startswith('gats.') for k in sd)
    if is_dual==is_binary:raise ValueError('Cannot determine original checkpoint architecture from state_dict')
    model_cls=GATDualClassification if is_dual else GATBinaryClassification
    model_cfg=cfg['model']
    method=cfg['preprocess']['method'];method_name=getattr(method,'name',method)
    if method_name not in ('RAW','RAW_WO_RENAME'):raise ValueError(f'Unsupported checkpoint preprocessing: {method_name}')
    from FiCoVuL.dataset.data_preprocess import DatasetName, PreprocessMethod
    if isinstance(method, str):
        try: method = PreprocessMethod[method]
        except KeyError: raise ValueError(f'Unknown checkpoint preprocess method: {method}')
    dataset=cfg['dataset_name']
    if isinstance(dataset, str):
        try: dataset = DatasetName[dataset]
        except KeyError: raise ValueError(f'Unknown checkpoint training dataset: {dataset}')
    init=dict(type_map=type_map,lexical_map=lexical_map,word_map=word_map,method=method,device=device,
              num_of_gat_layers=model_cfg['num_of_gat_layers'],
              num_heads_per_gat_layer=model_cfg['num_heads_per_gat_layer'],
              num_features_per_gat_layer=model_cfg['num_features_per_gat_layer'],
              add_skip_connection=model_cfg['add_skip_connection'],bias=model_cfg['bias'],
              num_of_relations=MINE_NUM_RELATIONS*(2 if model_cfg['add_reverse_edge'] else 1),
              dropout=model_cfg['dropout'],log_attention_weights=False,
              graph_representation_size=model_cfg['graph_representation_size'],
              num_heads_in_graph_representation=model_cfg['num_heads_in_graph_representation'],dataset=dataset)
    if is_dual:
        init['concat_gat_outputs']=bool(model_cfg.get('concat_gat_outputs',False))
        init['enable_global_exchange']=bool(model_cfg.get('enable_global_exchange',False))
    else: init['enable_global_exchange']=bool(model_cfg.get('enable_global_exchange',False))
    model=model_cls(**init)
    model.load_state_dict(sd,strict=True)
    model.to(device).eval()
    threshold=float(cfg.get('run',{}).get('classfication_threshold',0.5))
    if not 0<threshold<1:raise ValueError('Invalid checkpoint classification threshold')
    predictions=[];failures=[]
    for row in rows:
        gid=row['graph_id'];g=native['graphs'].get(gid)
        if g is None:
            failures.append({**{k:row[k] for k in ('sample_id','pair_id','version','graph_id')},'reason':'graph missing from model_ready/test.json'})
            continue
        try:
            feat,label,edges,node_graph,rpst=make_loader_item(g,cfg)
            feat=[[t.to(device) for t in x] for x in feat]
            with torch.inference_mode():
                outputs=model((feat,edges.to(device),node_graph.to(device)))
                logits=outputs[0] if is_dual else outputs
                if logits.numel()!=1:raise ValueError('Model produced !=1 graph logit')
                score=float(torch.sigmoid(logits.reshape(-1)[0]).item())
            predictions.append({'sample_id':row['sample_id'],'pair_id':row['pair_id'],
                'version':row['version'],'true_label':int(row['label']),
                'pred_label':int(score>threshold),'score_vulnerable':score,'graph_id':gid})
        except Exception as ex:
            failures.append({**{k:row[k] for k in ('sample_id','pair_id','version','graph_id')},
                'reason':f'{type(ex).__name__}: {str(ex)[:500]}'})
    rdir.mkdir(parents=True,exist_ok=True)
    preds_cols=['sample_id','pair_id','version','true_label','pred_label','score_vulnerable','graph_id']
    atomic_csv(rdir/'predictions.csv',predictions,preds_cols)
    atomic_csv(rdir/'raw_preds.csv',predictions,preds_cols)
    atomic_csv(rdir/'prediction_failures.csv',failures,['sample_id','pair_id','version','graph_id','reason'])
    grouped=defaultdict(dict)
    for p in predictions: grouped[p['pair_id']][p['version']]=p
    outcomes=Counter();pairs=0;score_drop=[]
    for key,group in grouped.items():
        if set(group)!= {'before','after'}:continue
        pairs+=1
        b,a=group['before'],group['after']
        outcome={(1,0):'correct_pair',(0,1):'inverted',(1,1):'both_vulnerable',(0,0):'both_benign'}[(b['pred_label'],a['pred_label'])]
        outcomes[outcome]+=1
        score_drop.append(b['score_vulnerable']-a['score_vulnerable'])
    metrics={
        'expected_samples':len(rows),'predicted_samples':len(predictions),
        'sample_coverage':len(predictions)/len(rows),
        'total_pairs':len(rows)//2,'evaluable_pairs':pairs,'pair_coverage':pairs/(len(rows)//2),
        'pair_accuracy':outcomes['correct_pair']/pairs if pairs else None,
        'label_change_rate':(outcomes['correct_pair']+outcomes['inverted'])/pairs if pairs else None,
        'outcomes':dict(outcomes),'mean_score_drop':sum(score_drop)/len(score_drop) if score_drop else None,
        'threshold':threshold,'architecture':'GATDualClassification' if is_dual else 'GATBinaryClassification',
        'device':str(device),'checkpoint':str(ckpt),'checkpoint_sha256':sha(ckpt.read_bytes()),
        'note':'Frozen checkpoint; function-level graph classifier. No node localization labels.'}
    atomic_json(rdir/'metrics.json',metrics)
    atomic_json(rdir/'run_metadata.json',{
        'model':'FiCoVuL','dataset_tag':args.dataset_tag,'run_id':args.run_id,
        'utc_finished':datetime.now(timezone.utc).isoformat(),
        'graph_manifest_sha256':sha((base/'manifest.csv').read_bytes()),
        'model_ready_sha256':sha(model_graph_file.read_bytes()),
        'vocab_sha256':{p:sha((Path(args.vocab_dir)/p).read_bytes()) for p in
          ('node_type_dict.pkl','word_lexical_dict.pkl','word_value_dict.pkl','most_common_function_names.txt')},
        'model_config':{k:str(v) for k,v in cfg['model'].items()},
        'preprocess_method':method_name,
        'no_test_time_training':True,'graph_provenance':'see work/<dataset-tag>/graph_status.csv'})
    print(json.dumps(metrics,indent=2))
    if args.strict and len(predictions)!=len(rows):raise RuntimeError(f'Coverage below 100%: {len(failures)} failures')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--stage',choices=['check','prepare','build','predict'],required=True)
    parser.add_argument('--samples',default=str(REPO/'datasets/processed/pairvul_top10/samples.csv'))
    parser.add_argument('--dataset-tag',default='pairvul_top10')
    parser.add_argument('--run-id',default='pairvul_top10_ficovul_01')
    parser.add_argument('--limit-pairs',type=int)
    parser.add_argument('--checkpoint')
    parser.add_argument('--vocab-dir',default=str(MODEL/'checkpoints/vocab'))
    parser.add_argument('--graph-dir')
    parser.add_argument('--device',choices=['cpu','cuda'],default='cpu')
    parser.add_argument('--strict',action='store_true')
    parser.add_argument('--overwrite',action='store_true')
    args=parser.parse_args(argv)
    # An upstream model can only be imported when cwd and sys.path allow FiCoVuL to resolve.
    sys.path.insert(0,str(MODEL))
    {'check':stage_check,'prepare':stage_prepare,'build':stage_build,'predict':stage_predict}[args.stage](args)
    return 0

if __name__=='__main__':
    try:raise SystemExit(main())
    except (ValueError,FileNotFoundError,FileExistsError,RuntimeError) as exc:
        print(f'ERROR: {exc}',file=sys.stderr);raise SystemExit(2)
