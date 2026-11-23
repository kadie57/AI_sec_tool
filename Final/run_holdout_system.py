"""Run the frozen existing system with Java comments masked in LLM code blocks.

Place in ~/AI_sec_tool. --check is offline; --run calls Ollama/Joern.
Original Java files, Sonar collection and reference labels are never modified.
This is an evaluation input policy, not an improvement in model reasoning.
Use the SAME comment policy for the direct-LLM baseline.
"""
import argparse
import functools
import hashlib
import json
from pathlib import Path
import re
import sys
from datetime import datetime, timezone

VERSION = "holdout-system-comment-mask-v1"
PLAN_HASH = "2e6bc2bd5ccd03c13463be32e87a4a00e60ffc944e414e273cfdb99732575436"
TOKENS = re.compile(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|//[^\n]*|/\*.*?\*/''', re.S)
BLOCK = re.compile(r'(\[MÃ NGUỒN(?: — DỮ LIỆU)?\]\n)(.*?)(\n\[HẾT MÃ NGUỒN\])', re.S)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def mask_java(source):
    # These Java lexical forms need a different lexer; fail instead of guessing.
    if '\\u' in source or '"""' in source:
        raise ValueError("Unicode escapes/text blocks require a separate input review.")
    result = TOKENS.sub(lambda m: re.sub(r'[^\r\n]', ' ', m[0])
                        if m[0].startswith(('//', '/*')) else m[0], source)
    if len(result) != len(source) or result.count('\n') != source.count('\n'):
        raise ValueError("Comment masking changed source coordinates.")
    return result


def numbered_mask(block):
    rows = block.split('\n')
    parsed = [re.fullmatch(r'(\d+): (.*)', line) for line in rows]
    if not parsed or any(x is None for x in parsed):
        raise ValueError("Unrecognized numbered Java block; no request sent.")
    if [int(x[1]) for x in parsed] != list(range(1, len(parsed) + 1)):
        raise ValueError("Non-contiguous source lines; no request sent.")
    clean = mask_java('\n'.join(x[2] for x in parsed)).split('\n')
    return '\n'.join(f'{i}: {line}' for i, line in enumerate(clean, 1))


def sanitize(request):
    if not isinstance(request, dict) or not isinstance(request.get('prompt'), str):
        raise ValueError("Unexpected model request.")
    old = request['prompt']
    new, count = BLOCK.subn(lambda m: m[1] + numbered_mask(m[2]) + m[3], old)
    if not count:
        # Existing ProcessBuilder adapter already applies code_only to MAIN/helpers.
        # Its identity is protected by planner.verify and its saved request retained.
        if '[MAIN]\n' not in old or '[/MAIN]' not in old:
            raise ValueError("No recognized source block; no request sent.")
    request['prompt'] = new
    return count, old != new


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--from-run', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--run', action='store_true')
    parser.add_argument('--retry-incomplete', action='store_true')
    args = parser.parse_args()
    root = Path.cwd().resolve()
    if Path(__file__).resolve().parent != root:
        raise ValueError('Đặt file trong ~/AI_sec_tool và chạy từ thư mục đó.')
    import prepare_owasp_holdout as planner
    import master_pipeline_multi_v1 as router
    work = root / 'experiments/owasp_holdout_v1'
    if sha((work / 'plan.json').read_bytes()) != PLAN_HASH:
        raise ValueError('Kế hoạch khác bản đã đối chiếu.')
    plan = planner.verify(root, work)
    collection = args.from_run.resolve()
    manifest, items = router.prepare(root, collection)
    if (manifest.get('plan_sha256') != PLAN_HASH or manifest.get('state') != 'COLLECTED'
            or manifest.get('benchmark_commit') != plan['benchmark_commit']):
        raise ValueError('Lượt thu thập không khớp kế hoạch đã duyệt.')
    planned = {row['project_path']: row['source_sha256'] for row in plan['samples']}
    for item in items:
        if item['route'] and planned.get(item['relative']) != sha(item['raw']):
            raise ValueError('Cảnh báo có nguồn ngoài kế hoạch.')
    changed = 0
    for row in plan['samples']:
        original = (root / row['project_path']).read_text(encoding='utf-8')
        changed += mask_java(original) != original
    policy = {'version': VERSION, 'script_sha256': sha(Path(__file__).read_bytes()),
              'plan_sha256': PLAN_HASH, 'source_policy': 'mask_all_java_comments_keep_lines',
              'original_sources_unchanged': True,
              'limitations': ['Public benchmark identifiers remain; no claim of training-data independence.',
                             'Comments are removed from model source blocks, not from archived sources.',
                             'ProcessBuilder uses its existing code_only preprocessing.',
                             'The direct-LLM baseline must use the same source comment policy.']}
    original_context = router.context_for
    def context_for(*a, **kw):
        context = original_context(*a, **kw)
        context['evaluation_input_policy'] = policy
        return context
    router.context_for = context_for
    audit_dir = None
    request_count = 0
    def before_send(request):
        nonlocal request_count
        count, changed = sanitize(request)
        request_count += 1
        if audit_dir is None:
            raise ValueError('Request attempted before audit log initialized.')
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        record = {'version': VERSION, 'request': request, 'source_block_count': count,
                  'comments_masked_now': changed,
                  'request_sha256': sha(json.dumps(request, ensure_ascii=False, sort_keys=True).encode())}
        path = audit_dir / f'{stamp}-{request_count:04d}.json'
        with path.open('x', encoding='utf-8') as stream:
            json.dump(record, stream, ensure_ascii=False, indent=2)
    original_configure = router.configure
    def configure(*a, **kw):
        modules, config, code = original_configure(*a, **kw)
        for name in ('path', 'command'):
            module = modules.get(name)
            if module is None:
                continue
            original_api = module.api
            def api(endpoint, payload=None, _api=original_api):
                if endpoint == '/api/generate':
                    before_send(payload)
                return _api(endpoint, payload)
            module.api = api
        if 'sql' in modules:
            import requests
            original_post = requests.post
            @functools.wraps(original_post)
            def post(url, *a, **kw):
                if str(url).rstrip('/').endswith('/api/generate'):
                    before_send(kw.get('json'))
                return original_post(url, *a, **kw)
            requests.post = post
        return modules, config, code
    router.configure = configure
    original_execute = router.execute
    def execute(root, collection, old, items, modules, config, context, retry=False):
        nonlocal audit_dir
        output = root / 'runs' / ('multi-' + collection.name + '-' + router.fingerprint(context)[:12])
        audit_dir = output / 'model_request_audit'
        audit_dir.mkdir(parents=True, exist_ok=True)
        return original_execute(root, collection, old, items, modules, config, context, retry)
    router.execute = execute
    print(f'INPUT_POLICY_OK: kiểm tra {len(plan["samples"])} mẫu; {changed} tệp có chú thích; nguồn gốc giữ nguyên.')
    sys.argv = [str(root / 'master_pipeline_multi_v1.py'), '--from-run', str(collection)]
    if args.check:
        sys.argv.append('--check')
    if args.retry_incomplete:
        sys.argv.append('--retry-incomplete')
    return router.main()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('Đã dừng; giữ checkpoint. Dùng --retry-incomplete nếu cảnh báo đang dở.')
        sys.exit(130)
    except Exception as exc:
        print('[LỖI]', str(exc), file=sys.stderr)
        sys.exit(1)
