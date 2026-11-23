"""Replay presentation only; no AI, Docker, SonarQube or original-result writes."""
import argparse
import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import path_triage_v2 as path_core


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path)
    args = parser.parse_args()
    if args.run:
        run = args.run.resolve()
    else:
        candidates = []
        for manifest_path in Path('runs').glob('*/manifest.json'):
            m = json.loads(manifest_path.read_text())
            if (m.get('state') == 'COMPLETED'
                    and m.get('prompt_versions') == {'path': 'path22-file-read-pilot-v4-evidence-scope'}):
                candidates.append((m.get('finished_at', ''), str(manifest_path.parent.resolve())))
        if not candidates:
            raise ValueError('Không tìm thấy lượt Path v4 hoàn tất. Dùng --run đường/dẫn/lượt/chạy.')
        run = Path(max(candidates)[1])
    rows_path = run / 'ai_results.json'
    raw_results = rows_path.read_bytes()
    rows = json.loads(raw_results)
    output = []
    for row in rows:
        if row.get('rule') != path_core.RULE or row.get('processing_status') != 'AI_PROPOSED':
            continue
        folder = (run / row['artifact_dir']).resolve()
        if not folder.is_relative_to(run):
            raise ValueError('Artifact ngoài thư mục kết quả.')
        source = (folder / 'source.java.txt').read_bytes()
        if hashlib.sha256(source).hexdigest() != row['source_sha256']:
            raise ValueError('Snapshot không khớp hash: ' + row['component'])
        for stage in ('source', 'path'):
            path_core.validate(row['model_assessment'][stage], stage, source.decode('utf-8'))
        composed = path_core.summarize_path_result(row)
        for key in ('verdict', 'ai_verdict', 'combined_verdict', 'decision_basis',
                    'model_assessment', 'evidence_lines', 'missing_context',
                    'requires_review', 'review_status', 'reviewed_verdict'):
            if composed.get(key) != row.get(key):
                raise ValueError('Replay thay đổi dữ liệu quyết định: ' + key)
        output.append({'component': row['component'], 'issue_id': row['issue_id'],
                       'source_sha256': row['source_sha256'],
                       'before': copy.deepcopy(row), 'after': composed})
        print(row['component'].split('/')[-1], '| giữ nhãn:', row['verdict'])
    if not output:
        raise ValueError('Không có kết quả Path phù hợp.')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    dest = Path('experiments/path_explanation_replay') / (stamp + '.json')
    dest.parent.mkdir(parents=True, exist_ok=True)
    report = {'experiment': 'path-scoped-summary-v1', 'source_run': str(run),
              'source_results_sha256': hashlib.sha256(raw_results).hexdigest(),
              'ai_calls': 0, 'semantic_revalidation': False,
              'note': 'Chỉ chuẩn hóa trình bày; giữ nguyên facts, nhãn và giải thích gốc.',
              'results': output}
    with dest.open('x', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print('LƯỢT NGUỒN:', run)
    print('ĐÃ LƯU:', dest.resolve())
    print('Không gọi AI; không sửa kết quả hoặc thẩm định cũ.')


if __name__ == '__main__':
    main()
