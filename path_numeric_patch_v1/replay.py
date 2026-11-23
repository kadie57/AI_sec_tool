"""Replay saved Path results; no AI, Docker, Sonar, or source execution."""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from path_guard_check_v1 import apply_check
from path_numeric_check_v1 import apply_numeric_check

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--run',type=Path,required=True)
a=p.parse_args()
run=a.run.resolve()
rows=json.loads((run/'ai_results.json').read_text())
output=[]
for row in rows:
    if row.get('analysis_route') != 'path':
        output.append(row); continue
    folder=(run/row['artifact_dir']).resolve()
    if not folder.is_relative_to(run): raise SystemExit('Invalid artifact path')
    raw=(folder/'source.java.txt').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=row['source_sha256']:
        raise SystemExit('Source hash mismatch; stopped without writing results.')
    result=apply_numeric_check(apply_check(row,raw.decode('utf-8'),row['line']),raw.decode('utf-8'),row['line'])
    output.append(result)
    print(Path(row['component']).name, '| AI:',row.get('ai_verdict'),
          '| sau kiểm tra:',result['verdict'],'|',result['numeric_check']['status'])
stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
dest=Path('experiments/path_numeric_replay')/stamp
(dest).mkdir(parents=True)
(dest/'results.json').write_text(json.dumps({'baseline_run':str(run),'ai_calls':0,
    'purpose':'bounded structural conflict check; not new AI accuracy evaluation',
    'checker_sha256':hashlib.sha256(Path(__file__).with_name('path_numeric_check_v1.py').read_bytes()).hexdigest(),
    'results':output},ensure_ascii=False,indent=2))
print('FILE CẦN GỬI:',(dest/'results.json').resolve())
