"""Replay the explanation merge on saved SQL artifacts; no service calls."""
import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
import replay_source_merge as merge


def read(p):
    return json.loads(p.read_text(encoding='utf-8'))


def replay(run, samples):
    manifest = read(run / 'manifest.json')
    if manifest.get('state') != 'COMPLETED':
        raise ValueError(f'Lượt chưa hoàn tất: {run}')
    rows = read(run / 'ai_results.json')
    output = []
    for row in rows:
        name = row.get('component', '').rsplit('/', 1)[-1]
        if name not in samples or row.get('processing_status') != 'AI_PROPOSED':
            continue
        if row.get('analysis_route') != 'sql':
            continue
        artifact = row.get('artifact_dir', '')
        if not re.fullmatch(r'issue-\d+', artifact):
            raise ValueError('Artifact không hợp lệ')
        folder = (run / artifact).resolve()
        def file(name):
            p = (folder / name).resolve()
            if not p.is_relative_to(run.resolve()):
                raise ValueError('Artifact nằm ngoài lượt chạy')
            return p
        raw = file('source.java.txt').read_bytes()
        source = raw.decode('utf-8')
        digest = hashlib.sha256(raw).hexdigest()
        if digest != row.get('source_sha256'):
            raise ValueError('Source hash không khớp: ' + name)
        stage = read(file('llm_stage2.json'))
        audit = read(file('llm_source_audit.json'))
        if audit.get('source_sha256') != digest:
            raise ValueError('Source audit khác nguồn: ' + name)
        numbered = '\n'.join(f'{i}: {line}' for i, line in enumerate(source.splitlines(), 1))
        prompt = stage['request_payload']['prompt']
        block = '[MÃ NGUỒN — DỮ LIỆU]\n' + numbered + '\n[HẾT MÃ NGUỒN]'
        if block not in prompt or not prompt.startswith(f"Thẩm định SQL injection tại dòng {row['line']}."):
            raise ValueError('Bước 2 khác nguồn/dòng: ' + name)
        audit_prompt = f"Kiểm tra nguồn dữ liệu tới SQL dòng {row['line']}.\n[MÃ NGUỒN]\n{numbered}\n[HẾT MÃ NGUỒN]"
        if audit['request_payload']['prompt'] != audit_prompt:
            raise ValueError('Audit khác nguồn/dòng: ' + name)
        new = merge.merge_assessments(stage, audit, source)
        if new['verdict'] != row.get('combined_verdict', row.get('verdict')):
            raise ValueError('Nhãn replay khác kết quả đã lưu; cần kiểm tra riêng: ' + name)
        output.append({'file': name, 'run': str(run.resolve()), 'issue_id': row.get('issue_id'),
            'source_sha256': digest, 'before': row['explanation'], 'after': new['explanation'],
            'verdict_before': row.get('combined_verdict', row.get('verdict')), 'result': new,
            'artifact_hashes': {n: hashlib.sha256(file(n).read_bytes()).hexdigest()
                               for n in ('llm_stage2.json','llm_source_audit.json')}})
    return output


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', type=Path, action='append', required=True)
    p.add_argument('--sample', action='append', required=True, help='Exact Java filename; selects only, never determines label')
    a = p.parse_args()
    if merge.audit.sha(Path(merge.core.__file__).read_bytes()) != merge.audit.CORE_HASH:
        raise ValueError('Core khác bản đã kiểm tra')
    rows = [r for run in a.run for r in replay(run, a.sample)]
    for name in a.sample:
        if sum(r['file'] == name for r in rows) != 1:
            raise ValueError('Cần đúng một cảnh báo đã phân tích cho mỗi mẫu: ' + name)
    out = Path('experiments/explanation_merge_v2')
    out.mkdir(parents=True, exist_ok=True)
    dest = out / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.json')
    payload = {'version': merge.VERSION, 'new_ai_calls': 0, 'original_runs_modified': False,
               'semantic_verification': 'REVIEW_REQUIRED', 'results': rows}
    with dest.open('x', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    for row in rows:
        print('\n' + row['file'] + ' | ' + row['result']['verdict'])
        print(row['after'])
    print('\nĐÃ LƯU:', dest.resolve())
    print('Chỉ kiểm chứng phép ghép trên artifact cũ; chưa đo lại chất lượng AI.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit('LỖI: ' + str(exc))
