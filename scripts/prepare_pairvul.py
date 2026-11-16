#!/usr/bin/env python3
"""Create auditable binary function samples from the Vul-RAG Linux kernel JSON.

This DOES NOT recreate the author's official 586-pair PairVul benchmark split.
It does not prove that a patched function is secure, or remove samples silently.
"""
import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


def codehash(code):
    return hashlib.sha256(code.encode('utf-8')).hexdigest()


def safe_tag(text):
    return re.sub(r'[^A-Za-z0-9_.-]', '_', str(text))


def prepare(input_path, output_dir, export_c=False):
    rows = json.loads(Path(input_path).read_text(encoding='utf-8'))
    if not isinstance(rows, list):
        raise ValueError('Expected a JSON list of pair dictionaries')
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    code_dir = output_dir / 'c_files'
    if export_c: code_dir.mkdir(exist_ok=True)
    manifest = []
    pairs = []
    seen_pairs = set()
    counts = Counter()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f'Row {index} is not a JSON object')
        cve = str(row.get('cve_id') or 'UNKNOWN')
        before = row.get('code_before_change')
        after = row.get('code_after_change')
        if not isinstance(before, str) or not isinstance(after, str):
            raise ValueError(f'Row {index} missing string before/after code')
        cwe = row.get('cwe') or []
        if isinstance(cwe, str): cwe = [cwe]
        if not isinstance(cwe, list): cwe = [str(cwe)]
        fingerprint = codehash(before + '\0' + after)
        pair_id = f'p{index:06d}_{fingerprint[:12]}'
        flags = []
        if not before.strip() or not after.strip(): flags.append('empty_code')
        if before == after: flags.append('identical_code')
        elif re.sub(r'\s+', '', before) == re.sub(r'\s+', '', after):
            flags.append('whitespace_only')
        if fingerprint in seen_pairs: flags.append('duplicate_pair')
        seen_pairs.add(fingerprint)
        if cve == 'UNKNOWN': flags.append('missing_cve')
        if not cwe: flags.append('missing_cwe')
        flags_value = ';'.join(flags)
        pairs.append({'pair_id': pair_id, 'source_row': index,
                      'original_id': row.get('id'), 'cve_id': cve,
                      'cwe': ';'.join(map(str,cwe)),
                      'before_sha256': codehash(before), 'after_sha256': codehash(after),
                      'quality_flags': flags_value})
        for version, code, label in [('before',before,1),('after',after,0)]:
            sample_id = pair_id + '__' + version
            outpath = f'c_files/{sample_id}.c' if export_c else ''
            if export_c: (output_dir / outpath).write_text(code,encoding='utf-8')
            manifest.append({'sample_id':sample_id,'pair_id':pair_id,
                             'source_row':index,'original_id':row.get('id'),
                             'cve_id':cve,'cwe':';'.join(map(str,cwe)),
                             'version':version,'label':label,
                             'source_sha256':codehash(code),
                             'quality_flags':flags_value,'code_file':outpath,
                             'processed_func':code,'target':label})
        counts.update(flags)
    def dump(name, records, fields):
        with (output_dir/name).open('w',newline='',encoding='utf-8') as h:
            w=csv.DictWriter(h,fieldnames=fields,extrasaction="ignore");w.writeheader();w.writerows(records)
    dump('pairs.csv',pairs,['pair_id','source_row','original_id','cve_id','cwe','before_sha256','after_sha256','quality_flags'])
    dump('samples.csv',manifest,['sample_id','pair_id','source_row','original_id','cve_id','cwe','version','label','source_sha256','quality_flags','code_file','processed_func','target'])
    dump('linevul_test.csv',manifest,['sample_id','pair_id','cve_id','cwe','version','source_sha256','processed_func','target'])
    report={'source':str(input_path),'source_pairs':len(pairs),'samples':len(manifest),
            'flag_counts':dict(counts), 'note':'No author test split or patch-history verification performed; review flags and external overlap before final evaluation.'}
    (output_dir/'dataset_report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return report


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input',required=True,type=Path,help='Linux_kernel_clean_data*.json')
    ap.add_argument('--out',required=True,type=Path,help='Example: datasets/processed/linux_top10_audit')
    ap.add_argument('--export-c',action='store_true',help='Write original source to one .c file per sample for graph extraction')
    args=ap.parse_args()
    print(json.dumps(prepare(args.input,args.out,args.export_c),indent=2))

if __name__=='__main__': main()
