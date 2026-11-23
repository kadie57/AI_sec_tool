"""Offline guard verification for saved command_triage_v1 artifacts (Python 3.10+).

python3 command_guard_replay_v1.py --collection runs/<Sonar collection>
or: python3 command_guard_replay_v1.py --from-run runs/<command78 result>

No network, Docker, Java execution or model calls. Original artifacts are read-only.
Recognizes a WHOLE, deliberately small Java compilation-unit grammar: one main,
args length check with throw, local String from args[0], conjunction of negated
String.equals literals with an uncaught throw, fixed ping command plus the same
local variable, immediate Runtime.exec(String), optional waitFor, then method end.
Every allowed value must be a strict dotted-decimal IPv4 address. No catch, finally,
extra methods/fields, mutations, wrappers, Unicode escapes or text blocks accepted.
This is a bounded recognizer, NOT a general Java parser or vulnerability verifier.
Unsupported syntax produces NOT_PROVEN, never a safety finding.
An accepted proof concerns input-driven command/option injection at this call only;
it does not certify the actual executable, privileges, destination authorization,
availability or other vulnerability classes. All proposals still require review.
The file/class/variable names, IP addresses and AI labels are not answer keys.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys

VERSION = "command78-finite-ipv4-allowlist-replay-v1"
BASE_VERSION = "command78-direct-exec-pilot-v1"
RULE = "findsecbugs:COMMAND_INJECTION"

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def fingerprint(data):
    return sha(json.dumps(data, sort_keys=True, ensure_ascii=False).encode())

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def strip_comments(source):
    # Preserve strings, character literals and newline offsets. Java Unicode
    # escape preprocessing/text blocks are rejected before this lexer is used.
    tokens = re.compile(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|//[^\n]*|/\*.*?\*/''', re.S)
    return tokens.sub(lambda m: re.sub(r"[^\n]", " ", m[0])
                      if m[0].startswith(("//", "/*")) else m[0], source)

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
LITERAL = r'"[^"\\\r\n]*"'
# Whole-unit matching is intentional. It establishes that the guard and sink
# are sequential in one method, with no catch/alternate branch/reassignment.
UNIT = re.compile(r"""
\s*(?:package\s+[A-Za-z_][\w.] *\s*;\s*)?
public\s+class\s+(?P<class>IDENT)\s*\{
\s*public\s+static\s+void\s+main\s*\(\s*String\s*\[\s*\]\s*(?P<args>IDENT)\s*\)
\s*throws\s+(?:java\.lang\.)?Exception\s*\{
\s*if\s*\(\s*(?P=args)\s*\.\s*length\s*!=\s*1\s*\)\s*\{
\s*throw\s+new\s+(?:java\.lang\.)?IllegalArgumentException\s*\(\s*LITERAL\s*\)\s*;\s*\}
\s*String\s+(?P<value>IDENT)\s*=\s*(?P=args)\s*\[\s*0\s*\]\s*;
\s*(?P<guard>if\s*\(\s*(?P<condition>.*?)\s*\)\s*\{
\s*throw\s+new\s+(?:java\.lang\.)?IllegalArgumentException\s*\(\s*LITERAL\s*\)\s*;\s*\})
\s*(?P<construction>String\s+(?P<command>IDENT)\s*=\s*"(?P<prefix>[^"\\\r\n]*)"\s*\+\s*(?P=value)\s*;)
\s*(?P<sink>(?:Process\s+(?P<process>IDENT)\s*=\s*)?
(?:java\.lang\.)?Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(\s*(?P=command)\s*\)\s*;)
\s*(?:(?P=process)\s*\.\s*waitFor\s*\(\s*\)\s*;\s*)?
\}\s*\}\s*
""".replace("IDENT", IDENT).replace("LITERAL", LITERAL), re.S | re.X)

def verify_guard(source, issue_line):
    def no(reason):
        return {"status": "NOT_PROVEN", "reason": reason,
                "proposed_verdict": None, "evidence_lines": []}
    if type(issue_line) is not int or not 1 <= issue_line <= len(source.splitlines()):
        return no("Dòng cảnh báo không hợp lệ.")
    if "\\u" in source or '"""' in source:
        return no("Unicode escapes/text blocks nằm ngoài phạm vi.")
    code = strip_comments(source)
    match = UNIT.fullmatch(code)
    if not match:
        return no("Code không khớp toàn bộ cấu trúc Java đơn giản được hỗ trợ.")
    if match['class'] in {"String", "Runtime", "Process", "Exception", "IllegalArgumentException"}:
        return no("Tên lớp che khuất kiểu Java chuẩn.")
    names = [match[g] for g in ("args", "value", "command", "process") if match[g]]
    if len(set(names)) != len(names) or any(n in {"Runtime", "java"} for n in names):
        return no("Định danh trùng hoặc che khuất tên cần phân giải.")
    term = r'!\s*' + re.escape(match['value']) + r'\s*\.\s*equals\s*\(\s*"([^"\\\r\n]*)"\s*\)'
    condition = match['condition']
    if not re.fullmatch(r'\s*' + term + r'(?:\s*&&\s*' + term + r')*\s*', condition):
        return no("Guard không phải phép AND của các so sánh khác giá trị cố định.")
    values = [m[1] for m in re.finditer(term, condition)]
    try:
        for value in values:
            if str(ipaddress.IPv4Address(value)) != value:
                raise ValueError("Noncanonical address")
    except ipaddress.AddressValueError:
        return no("Danh sách chứa giá trị không phải IPv4 chuẩn; không suy ra an toàn.")
    except ValueError:
        return no("IPv4 không ở dạng chuẩn.")
    # Narrow scope makes token/option conclusions explicit, not generic to every
    # program accepting an IP-shaped string. No executable is run here.
    if not re.fullmatch(r"(?:(?:/usr/bin|/bin)/)?ping -c [1-9][0-9]* ", match['prefix']):
        return no("Chỉ kiểm chứng tiền tố cố định ping -c <số nguyên dương>.")
    def line_at(pos):
        return code[:pos].count("\n") + 1
    first, last = line_at(match.start('sink')), line_at(match.end('sink')-1)
    if not first <= issue_line <= last:
        return no("Lời gọi đã kiểm chứng không nằm tại dòng cảnh báo.")
    evidence = set()
    for group in ('guard', 'construction', 'sink'):
        evidence.update(range(line_at(match.start(group)), line_at(match.end(group)-1)+1))
    lines = source.splitlines()
    return {"status": "PROVEN_WITHIN_BOUNDED_GRAMMAR", "proposed_verdict": "LIKELY_FP",
            "decision_basis": "STATIC_FINITE_IPV4_ALLOWLIST", "execution_kind": "DIRECT_EXEC",
            "allowed_values": list(dict.fromkeys(values)),
            "possible_commands": [match['prefix'] + v for v in dict.fromkeys(values)],
            "evidence_lines": sorted(evidence),
            "resolved_evidence": [{"line": n, "code": lines[n-1]} for n in sorted(evidence)],
            "reason": "Giá trị ngoài danh sách bị throw trước exec, không có catch hoặc thay đổi giá trị sau guard. "
                      "Các IPv4 được phép không chứa khoảng trắng, không bắt đầu bằng dấu trừ; "
                      "chỉ thay đổi một đối số địa chỉ trong lệnh ping cố định.",
            "scope": "Chỉ cơ chế chèn lệnh/đối số do đầu vào tại lời gọi này; không đánh giá toàn bộ chương trình hoặc môi trường.",
            "requires_review": True}

def locate(args):
    if args.from_run:
        return args.from_run.resolve()
    collection = args.collection.resolve()
    candidates = []
    for p in collection.parent.glob(collection.name + '-command78-*'):
        if (p/'manifest.json').is_file() and read(p/'manifest.json').get('pipeline_version') == BASE_VERSION:
            candidates.append(p)
    if len(candidates) != 1:
        raise ValueError("Cần đúng một lượt Command v1; dùng --from-run để chọn. Tìm thấy: "
                         + ', '.join(str(p) for p in candidates))
    return candidates[0]

def replay(run):
    manifest = read(run/'manifest.json')
    if manifest.get('pipeline_version') != BASE_VERSION or manifest.get('state') != 'COMPLETED':
        raise ValueError('Cần lượt Command v1 đã COMPLETED.')
    rows = read(run/'ai_results.json')
    if not isinstance(rows, list) or not rows:
        raise ValueError('Kết quả không phải danh sách cảnh báo.')
    outputs, hashes = [], {}
    for row in rows:
        if row.get('rule') != RULE:
            continue
        artifact = row.get('artifact_dir', '')
        if not isinstance(artifact, str) or not re.fullmatch(r'issue-\d+', artifact):
            raise ValueError('artifact_dir không hợp lệ.')
        folder = (run/artifact).resolve()
        if not folder.is_relative_to(run):
            raise ValueError('Artifact nằm ngoài lượt chạy.')
        raw = (folder/'source.java.txt').read_bytes()
        if sha(raw) != row['source_sha256']:
            raise ValueError('Snapshot không khớp hash: ' + artifact)
        source = raw.decode('utf-8')
        saved_path = folder/'llm_command.json'
        saved = read(saved_path)
        if saved.get('error_kind') is not None or not saved.get('facts'):
            raise ValueError('Lượt AI có lỗi; cần kiểm tra riêng: ' + artifact)
        body = saved.get('ollama_response') or {}
        if body.get('done') is not True or body.get('done_reason') == 'length':
            raise ValueError('Lượt sinh AI chưa hoàn tất: ' + artifact)
        if 'java/lang/Runtime.exec(Ljava/lang/String;)' not in row.get('message', ''):
            raise ValueError('Không có mô tả Runtime.exec(String) để đối chiếu API.')
        if saved['facts'] != row.get('model_assessment', {}).get('command'):
            raise ValueError('Facts AI không khớp kết quả tổng hợp: ' + artifact)
        request = saved['request_payload']
        prompt = request['prompt']
        start, end = '[MÃ NGUỒN]\n', '\n[HẾT MÃ NGUỒN]'
        if prompt.count(start) != 1 or prompt.count(end) != 1:
            raise ValueError('Khối nguồn trong prompt không xác định duy nhất.')
        expected = '\n'.join(f'{n}: {line}' for n, line in enumerate(source.splitlines(), 1))
        if prompt.split(start, 1)[1].split(end, 1)[0] != expected:
            raise ValueError('Nguồn đã gửi AI khác snapshot: ' + artifact)
        if request.get('model') != row.get('model') or row.get('prompt_version') != BASE_VERSION:
            raise ValueError('Model/version không khớp kết quả.')
        assessment = verify_guard(source, row['line'])
        new = assessment['proposed_verdict'] or row['verdict']
        outputs.append({'issue_id': row['issue_id'], 'component': row['component'],
            'line': row['line'], 'source_sha256': sha(raw),
            'original_verdict': row['verdict'], 'original_ai_verdict': row.get('ai_verdict'),
            'original_model_assessment': row.get('model_assessment'),
            'static_assessment': assessment, 'proposed_combined_verdict': new,
            'decision_origin': 'STATIC_GUARD' if assessment['proposed_verdict'] else 'UNCHANGED_BASELINE',
            'review_status': 'PENDING', 'reviewed_verdict': None, 'requires_review': True})
        hashes[artifact] = {'source_sha256': sha(raw), 'llm_command_sha256': sha(saved_path.read_bytes())}
    if not outputs:
        raise ValueError('Không có cảnh báo Command Injection.')
    return outputs, hashes

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--collection', type=Path)
    group.add_argument('--from-run', type=Path)
    args = parser.parse_args()
    run = locate(args)
    rows, hashes = replay(run)
    context = {'version': VERSION, 'script_sha256': sha(Path(__file__).read_bytes()),
        'run': str(run), 'results_sha256': sha((run/'ai_results.json').read_bytes()),
        'manifest_sha256': sha((run/'manifest.json').read_bytes()), 'artifacts': hashes}
    folder = Path('experiments/command_guard_replay_v1') / fingerprint(context)[:20]
    folder.mkdir(parents=True, exist_ok=True)
    path = folder/'comparison.json'
    report = {'context': context, 'results': rows, 'new_ai_calls': 0,
        'pipeline_integrated': False, 'review_required': True,
        'limitations': ['Bounded single-method grammar only; unsupported code is NOT_PROVEN.',
            'Static proposal does not correct or retrain the model.',
            'No held-out accuracy claim; no automatic Sonar issue closure.']}
    if path.exists():
        if read(path) != report:
            raise ValueError('Kết quả lưu khác nội dung; không ghi đè.')
    else:
        with path.open('x', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    for row in rows:
        print(row['component'], '| trước:', row['original_verdict'],
              '| sau ghép:', row['proposed_combined_verdict'],
              '| kiểm tra:', row['static_assessment']['status'])
    print('Không gọi AI; chưa sửa pipeline; giữ nguyên nhãn AI gốc. Đề xuất vẫn cần thẩm định.')
    print('FILE CẦN GỬI:', path.resolve())
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print('[LỖI]', exc, file=sys.stderr)
        sys.exit(1)
