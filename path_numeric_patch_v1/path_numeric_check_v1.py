"""Bounded lexical path check; no input program execution, no automatic FP approval."""
import copy
import hashlib
from path_guard_check_v1 import Parser, OutsideScope

VERSION = 'path-numeric-conflict-v1'

def inspect(source, issue_line):
    out = dict(version=VERSION, status='NOT_CHECKED', evidence_lines=[],
               source_sha256=hashlib.sha256(source.encode()).hexdigest(),
               scope='single main; standard Java Long decimal conversion; direct File(String) read',
               assumptions=['Standard java.lang types; no package-level type shadowing.'],
               proves_filesystem_confinement=False)
    try:
        p = Parser(source)
        if p.peek() == 'package':
            p.take(); p.ident()
            while p.peek() == '.':
                p.take(); p.ident()
            p.take(';')
        p.imports = set()
        while p.peek() == 'import':
            p.seq('import java . io .'); name = p.ident()
            if name not in ('File', 'FileInputStream'):
                raise OutsideScope('Unsupported import.')
            p.imports.add(name); p.take(';')
        p.seq('public class'); cls = p.ident(); p.take('{')
        p.seq('public static void main ( String [ ]'); args = p.ident()
        p.seq(') throws Exception { if ('); p.take(args)
        p.seq('. length != 1 ) throw new IllegalArgumentException ( ) ; String')
        value = p.ident(); p.take('='); p.take(args); p.seq('[ 0 ] ;')
        _, conversion = p.take(value)
        p.seq('= Long . toString ( Long . parseLong ('); p.take(value); p.seq(') ) ; String')
        full = p.ident(); p.take('='); prefix, join = p.string()
        if not prefix.startswith('/') or not prefix.endswith('/') or '..' in prefix.split('/'):
            raise OutsideScope('Unsupported base directory.')
        p.take('+'); p.take(value); p.take(';')
        p.type('File'); filevar = p.ident(); p.seq('= new')
        sink = p.ts[p.i][1]; p.type('File'); p.take('('); p.take(full)
        p.seq(') ; try ('); p.type('FileInputStream'); stream = p.ident()
        p.seq('= new'); p.type('FileInputStream'); p.take('('); p.take(filevar)
        p.seq(') ) { System . out . println ('); p.take(stream)
        p.seq('. read ( ) ) ; } } }')
        names = [args, value, full, filevar, stream]
        reserved = {'java', 'String', 'Long', 'System', 'Exception', 'IllegalArgumentException', 'File', 'FileInputStream'}
        if p.i != len(p.ts) or sink != issue_line or len(set(names)) != 5 or any(n in reserved for n in names + [cls]):
            raise OutsideScope('Extra code, wrong issue line, or identifier shadowing.')
        out.update(status='CHECKED', value_form='DECIMAL_LONG', evidence_lines=sorted({conversion, join, sink}),
                   reason='Giá trị tới File(String) đã qua Long.parseLong rồi Long.toString, không bị ghi đè. Nếu chuyển đổi thành công, phần tên chỉ là chữ số thập phân và có thể có dấu trừ; nếu thất bại, ngoại lệ thoát main trước thao tác file. Không xác nhận trạng thái symlink hoặc quyền truy cập filesystem.')
    except (OutsideScope, IndexError) as exc:
        out['reason'] = str(exc)
    return out

def apply_numeric_check(row, source, issue_line):
    result = copy.deepcopy(row)
    check = inspect(source, issue_line)
    result['numeric_check'] = check
    if (check['status'] == 'CHECKED' and row.get('processing_status') == 'AI_PROPOSED'
        and not row.get('error_kind') and row.get('path_effect') == 'ESCAPABLE'
        and row.get('decision_origin') != 'STATIC_NUMERIC_CONFLICT'):
        for key in ('verdict', 'explanation', 'evidence_lines', 'missing_context', 'decision_basis'):
            result.setdefault('ai_' + key, copy.deepcopy(row.get(key)))
        result['pre_numeric_result'] = copy.deepcopy(row)
        reason = 'Cần thẩm định mâu thuẫn: AI báo ESCAPABLE nhưng giá trị đã chuyển thành chuỗi số thập phân trước thao tác file.'
        result.update(verdict='UNKNOWN', combined_verdict='UNKNOWN', decision_origin='STATIC_NUMERIC_CONFLICT',
                      decision_basis='NUMERIC_CONTRADICTION', explanation=reason + '\n' + check['reason'],
                      evidence_lines=sorted(set(row.get('evidence_lines', []) + check['evidence_lines'])),
                      missing_context=list(dict.fromkeys(row.get('missing_context', []) + [reason])),
                      requires_review=True, review_status='PENDING', reviewed_verdict=None)
    return result
