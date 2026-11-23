"""Frozen follow-up evaluation; labels are read ONLY by score."""
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def read(p):
    return json.loads(p.read_text(encoding='utf-8'))

def save(p, data):
    with p.open('x', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def frozen_hashes():
    files = list(ROOT.glob('*.py')) + list(BASE.glob('*.py')) + list(BASE.glob('*.json'))
    files += list((BASE / 'sources').glob('*.java'))
    return {str(p.relative_to(ROOT)): sha(p) for p in sorted(files) if p.name != 'freeze.json'}

def verify(suite):
    freeze = read(BASE / 'freeze.json')
    if freeze['hashes'] != frozen_hashes():
        raise ValueError('Code/cấu hình/bộ mẫu đã đổi sau khi chốt; không trộn vào cùng lượt đánh giá.')
    for s in suite:
        if sha(ROOT / s['path']) != s['sha256']:
            raise ValueError('Mẫu cài đặt bị thay đổi: ' + s['sample'])

def collection_data(folder, suite):
    folder = folder.resolve()
    m = read(folder / 'manifest.json')
    if m.get('state') not in ('COLLECTED', 'COMPLETED'):
        raise ValueError('Lượt thu thập chưa hoàn tất.')
    for s in suite:
        if m.get('source_hashes', {}).get(s['path']) != s['sha256']:
            raise ValueError('Lượt thu thập thiếu/khác mẫu mới: ' + s['sample'])
    data = read(folder / 'issues.json')
    issues = data if isinstance(data, list) else data['issues']
    groups = {}
    for s in suite:
        comp = m['project'] + ':' + s['path']
        groups[s['sample']] = [i for i in issues if i.get('component') == comp and i.get('rule') == s['rule']]
    return m, groups

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('action', choices=['init', 'inventory', 'analyze', 'score'])
    ap.add_argument('--collection', type=Path)
    ap.add_argument('--result-run', type=Path)
    ap.add_argument('--retry-incomplete', action='store_true')
    a = ap.parse_args()
    suite = read(BASE / 'suite.json')['samples']
    if a.action == 'init':
        for name in ('master_pipeline.py', 'master_pipeline_multi_v1.py'):
            if not (ROOT / name).is_file():
                raise ValueError('Giải nén thư mục eval_followup_v1 ngay trong ~/AI_sec_tool.')
        for s in suite:
            src = BASE / 'sources' / (s['sample'] + '.java')
            if sha(src) != s['sha256']:
                raise ValueError('Bộ mẫu không khớp manifest.')
            dst = ROOT / s['path']
            if dst.exists() and sha(dst) != s['sha256']:
                raise ValueError('Không ghi đè mẫu khác: ' + str(dst))
        # Compile only, NEVER execute sample classes.
        with tempfile.TemporaryDirectory(prefix='eval-java-') as tmp:
            subprocess.run(['javac', '-g', '-d', tmp] + [str(BASE/'sources'/(s['sample']+'.java')) for s in suite], check=True)
        for s in suite:
            dst = ROOT / s['path']
            dst.parent.mkdir(parents=True, exist_ok=True)
            if not dst.exists():
                with dst.open('xb') as f:
                    f.write((BASE/'sources'/(s['sample']+'.java')).read_bytes())
        if (BASE/'freeze.json').exists():
            verify(suite)
        else:
            save(BASE/'freeze.json', {'created_at': datetime.now(timezone.utc).isoformat(), 'hashes': frozen_hashes()})
        print('INIT_OK: biên dịch 12 mẫu; cài vào Clean_Code/eval_followup21; đã chốt hash. Không chạy mẫu Java/AI.')
        return
    verify(suite)
    if a.collection is None:
        raise ValueError('Cần --collection runs/TEN_LUOT_THU_THAP_MOI')
    m, groups = collection_data(a.collection, suite)
    if a.action == 'inventory':
        dest = BASE/('inventory_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.txt')
        lines = ['Collection: '+str(a.collection.resolve())]
        for s in suite:
            issues=groups[s['sample']]
            lines.append(s['sample']+' | '+s['group']+' | '+str(len(issues))+' cảnh báo đúng rule | '+('FOUND' if issues else 'NO_ALERT'))
        # txt output is intentionally excluded from frozen inputs.
        dest.write_text('\n'.join(lines)+'\n',encoding='utf-8')
        print('\n'.join(lines));print('ĐÃ LƯU:',dest)
        return
    if a.action == 'analyze':
        selected=[m['project']+':'+s['path'] for s in suite if groups[s['sample']]]
        if not selected:
            raise ValueError('Không có cảnh báo phù hợp; không gọi AI.')
        cmd=[sys.executable,str(ROOT/'master_pipeline_multi_v1.py'),'--from-run',str(a.collection.resolve())]
        for comp in selected:cmd+=['--only-component',comp]
        if a.retry_incomplete:cmd+=['--retry-incomplete']
        subprocess.run(cmd+['--check'],cwd=ROOT,check=True)
        subprocess.run(cmd,cwd=ROOT,check=True)
        return
    if not a.result_run:
        raise ValueError('Cần --result-run runs/TEN_LUOT_AI')
    rm=read(a.result_run/'manifest.json')
    if rm.get('state')!='COMPLETED' or Path(rm['parent_run']).resolve()!=a.collection.resolve():
        raise ValueError('Lượt AI chưa xong hoặc không thuộc collection này.')
    results=read(a.result_run/'ai_results.json')
    index={r['issue_id']:r for r in results}
    refs={r['sample']:r for r in read(BASE/'reference_labels.json')['references']}
    records=[]; matrices={g:Counter() for g in ('ai','combined')};errors=Counter();missing=0
    for s in suite:
        ref=refs[s['sample']]; hits=groups[s['sample']]
        if not hits:
            missing+=1;records.append({'sample':s['sample'],'status':'NO_ALERT','reference':ref});continue
        for issue in hits:
            r=index.get(issue['key'])
            if not r or r.get('source_sha256')!=s['sha256']:
                raise ValueError('Thiếu/sai nguồn kết quả: '+s['sample'])
            eligible=ref['evaluation_group']=='core'
            ok=r.get('processing_status')=='AI_PROPOSED' and r.get('error_kind') is None
            if not ok:errors[r.get('error_kind') or r.get('processing_status')]+=1
            if eligible:
                for channel,field in (('ai','ai_verdict'),('combined','verdict')):
                    pred=r.get(field) if ok else 'NOT_ANALYZED'
                    matrices[channel][ref['reference_verdict']+' -> '+str(pred)]+=1
            records.append({'sample':s['sample'],'issue_id':issue['key'],'reference':ref,
                            'ai_verdict':r.get('ai_verdict'),'combined_verdict':r.get('verdict'),
                            'decision_origin':r.get('decision_origin'),'processing_status':r.get('processing_status'),
                            'error_kind':r.get('error_kind'),'included_in_core_matrix':eligible})
    dest=BASE/'scores';dest.mkdir(exist_ok=True)
    out=dest/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.json')
    save(out,{'suite_size':len(suite),'samples_without_alert':missing,'unit':'warning; multiple warnings per file retained',
              'label_status':'AUTHOR_PROPOSED_REVIEW_REQUIRED','core_confusion':{g:dict(c) for g,c in matrices.items()},
              'errors_or_abstentions':dict(errors),'explanation_quality':'NOT_SCORED_NEEDS_CODE_REVIEW',
              'collection':str(a.collection.resolve()),'result_run':str(a.result_run.resolve()),
              'freeze_sha256':sha(BASE/'freeze.json'),'results_sha256':sha(a.result_run/'ai_results.json'),
              'records':records})
    print('ĐÃ LƯU:',out)

if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,subprocess.CalledProcessError) as e:
        raise SystemExit('LỖI: '+str(e))
