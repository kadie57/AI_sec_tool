"""Bounded structural check, not a general Java verifier. Never executes input code."""
import copy
import hashlib
import re

VERSION = 'path-catch-guard-check-v1'
TOKEN = re.compile(r'\s+|//[^\n]*|/\*[\s\S]*?\*/|"[^"\\\r\n]*"|[A-Za-z_$][A-Za-z0-9_$]*|[0-9]+|!=|[{}()\[\].,;!+*=<>-]')

class OutsideScope(ValueError):
    pass

class Parser:
    def __init__(self, source):
        if '\\' in source:
            raise OutsideScope('Escapes/unicode escapes are outside scope.')
        self.ts = []
        pos = 0
        while pos < len(source):
            m = TOKEN.match(source, pos)
            if not m:
                raise OutsideScope('Unsupported token.')
            s = m.group()
            if not s.isspace() and not s.startswith(('//', '/*')):
                self.ts.append((s, source.count('\n', 0, pos) + 1))
            pos = m.end()
        self.i = 0
    def peek(self):
        return self.ts[self.i][0] if self.i < len(self.ts) else None
    def take(self, expected=None):
        if self.i >= len(self.ts):
            raise OutsideScope('Unexpected end.')
        token, line = self.ts[self.i]
        if expected is not None and token != expected:
            raise OutsideScope('Structure outside supported grammar.')
        self.i += 1
        return token, line
    def seq(self, text):
        for t in text.split():
            self.take(t)
    def ident(self):
        s, _ = self.take()
        if not re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*', s):
            raise OutsideScope('Expected identifier.')
        return s
    def string(self):
        s, line = self.take()
        if not s.startswith('"'):
            raise OutsideScope('Expected literal.')
        return s[1:-1], line
    def type(self, simple):
        if self.peek() == 'java':
            self.seq('java . io . ' + simple)
        elif simple in self.imports:
            self.take(simple)
        else:
            raise OutsideScope('Unresolved I/O type.')

def inspect(source, issue_line):
    base = {'version': VERSION, 'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
            'scope': 'single main, direct regex throw/catch, unchanged value, File(String) read',
            'status': 'NOT_CHECKED', 'evidence_lines': [], 'proves_vulnerability': False}
    try:
        p = Parser(source)
        if p.peek() == 'package':
            p.take(); p.ident()
            while p.peek() == '.':
                p.take(); p.ident()
            p.take(';')
        p.imports = set()
        while p.peek() == 'import':
            p.seq('import java . io .')
            name = p.ident()
            if name not in ('File', 'FileInputStream'):
                raise OutsideScope('Unsupported import.')
            p.imports.add(name); p.take(';')
        p.seq('public class'); cls = p.ident(); p.take('{')
        p.seq('public static void main ( String [ ]'); args = p.ident()
        p.seq(') throws Exception { if ('); p.take(args)
        p.seq('. length != 1 ) throw new IllegalArgumentException ( ) ; String')
        value = p.ident(); p.seq('='); p.take(args); p.seq('[ 0 ] ; try { if ( !')
        _, guard_line = p.take(value); p.seq('. matches (')
        pattern, _ = p.string()
        if not re.fullmatch(r'\[A-Za-z0-9_\]\{1,[1-9][0-9]*\}', pattern):
            raise OutsideScope('Unsupported allowlist.')
        p.seq(') ) throw new IllegalArgumentException ( ) ; }')
        _, catch_line = p.take('catch'); p.seq('( IllegalArgumentException')
        exc = p.ident(); p.seq(') {')
        if p.peek() == 'return':
            p.seq('return ;'); behavior = 'CATCH_EXITS'
        elif p.peek() == 'throw':
            p.take(); p.take(exc); p.take(';'); behavior = 'CATCH_EXITS'
        elif p.peek() == 'System':
            p.seq('System . out . println ('); p.string(); p.seq(') ;')
            behavior = 'CATCH_CONTINUES'
        elif p.peek() == '}':
            behavior = 'CATCH_CONTINUES'
        else:
            raise OutsideScope('Unsupported catch body.')
        p.seq('} String'); full = p.ident(); p.take('=')
        prefix, _ = p.string()
        if not prefix.startswith('/') or not prefix.endswith('/') or '..' in prefix.split('/'):
            raise OutsideScope('Unsupported base directory.')
        p.take('+'); p.take(value); p.take(';')
        p.type('File'); filevar = p.ident(); p.seq('= new')
        sink_line = p.ts[p.i][1]
        p.type('File'); p.take('('); p.take(full); p.seq(') ; try (')
        p.type('FileInputStream'); stream = p.ident(); p.seq('= new')
        p.type('FileInputStream'); p.take('('); p.take(filevar); p.seq(') ) {')
        p.seq('System . out . println ('); p.take(stream); p.seq('. read ( ) ) ; } } }')
        if p.i != len(p.ts) or sink_line != issue_line:
            raise OutsideScope('Extra code or wrong issue line.')
        if len({args, value, exc, full, filevar, stream}) != 6 or cls in {'java', 'String', 'System', 'Exception', 'IllegalArgumentException', 'File', 'FileInputStream'}:
            raise OutsideScope('Identifier shadowing outside scope.')
        base.update(status='CHECKED', guard_behavior=behavior,
                    evidence_lines=sorted({guard_line, catch_line, sink_line}),
                    reason=('Nhánh từ chối ném ngoại lệ, catch cho chạy tiếp; giá trị không đổi tới File(String).'
                            if behavior == 'CATCH_CONTINUES' else
                            'Nhánh từ chối thoát main bằng return hoặc ném lại ngoại lệ; không tới File(String).'))
    except OutsideScope as e:
        base['reason'] = str(e)
    return base

def apply_check(row, source, issue_line):
    result = copy.deepcopy(row)
    check = inspect(source, issue_line)
    result['guard_check'] = check
    if (result.get('processing_status') == 'AI_PROPOSED' and not result.get('error_kind')
        and check.get('guard_behavior') == 'CATCH_CONTINUES'
        and result.get('path_effect') == 'CONFINED'):
        for key in ('verdict', 'explanation', 'evidence_lines', 'missing_context', 'decision_basis'):
            result.setdefault('ai_' + key, copy.deepcopy(row.get(key)))
        result['pre_guard_result'] = copy.deepcopy(row)
        reason = 'Mâu thuẫn: AI báo CONFINED nhưng kiểm tra cấu trúc xác nhận nhánh từ chối vẫn tới thao tác file với giá trị không đổi.'
        result.update(verdict='UNKNOWN', combined_verdict='UNKNOWN',
                      decision_origin='STATIC_GUARD_CONFLICT', decision_basis='GUARD_CONTRADICTION',
                      explanation=reason + '\n' + check['reason'], requires_review=True,
                      review_status='PENDING', reviewed_verdict=None,
                      evidence_lines=sorted(set(row.get('evidence_lines', []) + check['evidence_lines'])),
                      missing_context=list(dict.fromkeys(row.get('missing_context', []) + [reason])))
    return result
