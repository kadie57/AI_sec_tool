"""Read-only display of supplied verification receipts; no execution or service calls."""
import hashlib
import json
from pathlib import Path

DATA = Path(__file__).resolve().parent / 'patch_evidence'

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def load(proposal):
    if not isinstance(proposal, dict):
        return None
    try:
        hashes = json.loads((DATA / 'hashes.json').read_text())
        required = {'comparison.json', 'proposal.json', 'reviewed.java.txt'}
        if set(hashes) != required:
            raise ValueError('Danh sách bằng chứng không hợp lệ.')
        files = {}
        for name in required:
            path = DATA / name
            if path.is_symlink() or path.stat().st_size > 2_000_000:
                raise ValueError('Tệp bằng chứng không hợp lệ.')
            raw = path.read_bytes()
            if sha(raw) != hashes[name]:
                raise ValueError('Bằng chứng đã thay đổi; chưa hiển thị kết luận.')
            files[name] = raw
        expected = json.loads(files['proposal.json'])
        if proposal != expected:
            return None
        report = json.loads(files['comparison.json'])
        variants = report['variants']
        verification = report['runtime_verification_v2']
        source = files['reviewed.java.txt']
        if (report['state'] != 'COMPLETED'
                or variants['original']['result']['source_sha256'] != proposal['source_sha256']
                or variants['proposed']['result']['source_sha256'] != sha(proposal['proposal']['updated_source'].encode())
                or variants['reviewed_v2']['result']['source_sha256'] != sha(source)
                or verification['signature']['source_sha256'] != sha(source)):
            raise ValueError('Bản sửa và kết quả kiểm chứng không khớp.')
        checks = verification['checks']
        resources = verification['resource_checks']
        changes = verification['controlled_interleavings']
        passed = (verification['state'] == 'PASSED' and bool(checks) and bool(resources) and bool(changes)
                  and all(x['passed'] is True for x in checks + resources)
                  and all(x['blocked_without_output'] is True for x in changes))
        return {'error': '', 'passed': passed, 'source': source.decode(),
                'checks': checks, 'resources': resources, 'changes': changes,
                'check_count': sum(x['passed'] is True for x in checks),
                'resource_count': sum(x['passed'] is True for x in resources),
                'blocked_count': sum(x['blocked_without_output'] is True for x in changes),
                'report': report, 'path_count': variants['reviewed_v2']['result']['target_rule_count']}
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        return {'error': 'Không xác minh được hồ sơ kiểm chứng: ' + str(exc)}
