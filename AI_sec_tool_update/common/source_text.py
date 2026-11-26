"""Mask Java comments while retaining source coordinates."""

import re

TOKENS = re.compile(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|//[^\n]*|/\*.*?\*/''', re.S)


def mask_java(source):
    # These Java lexical forms need a different lexer; fail instead of guessing.
    if '\\u' in source or '"""' in source:
        raise ValueError("Unicode escapes/text blocks require a separate input review.")
    result = TOKENS.sub(lambda m: re.sub(r'[^\r\n]', ' ', m[0])
                        if m[0].startswith(('//', '/*')) else m[0], source)
    if len(result) != len(source) or result.count('\n') != source.count('\n'):
        raise ValueError("Comment masking changed source coordinates.")
    return result
