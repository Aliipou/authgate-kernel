#!/usr/bin/env python3
"""Find real `sorry` / `admit` in Lean sources, ignoring comments.

Why this is a separate script rather than a grep.

`sorry` is discussed constantly in this repository's Lean comments -- Scope.lean
alone says "Was `sorry`. Now fully proved" four times, and TCB.lean's header
narrates which proofs used to have placeholders. A naive
`grep -nE '\\bsorry\\b'` therefore reports seven hits on a development that
contains none, and a CI job built on that grep fails a green build forever.
That is the same class of defect this repository was audited for on 2026-08-06:
a check that cannot distinguish the thing from talk about the thing.

So this strips Lean comments first -- `--` to end of line, and `/- ... -/`
blocks, which nest in Lean 4 -- and only then looks for the tokens.

Exit 0 if clean, 1 if any real occurrence is found.
Usage: python scripts/lean_sorry_check.py [root]   (default: formal)
"""
import io
import os
import re
import sys

TOKENS = re.compile(r'(?<![A-Za-z0-9_])(sorry|admit)(?![A-Za-z0-9_])')


def strip_comments(src):
    """Remove Lean 4 comments, preserving newlines so line numbers survive."""
    out = []
    i = 0
    n = len(src)
    depth = 0          # nesting depth of /- -/
    while i < n:
        two = src[i:i + 2]
        if depth > 0:
            if two == '/-':
                depth += 1
                out.append('  ')
                i += 2
                continue
            if two == '-/':
                depth -= 1
                out.append('  ')
                i += 2
                continue
            out.append('\n' if src[i] == '\n' else ' ')
            i += 1
            continue
        if two == '/-':
            depth = 1
            out.append('  ')
            i += 2
            continue
        if two == '--':
            # line comment: blank to end of line
            j = src.find('\n', i)
            if j == -1:
                out.append(' ' * (n - i))
                i = n
            else:
                out.append(' ' * (j - i))
                i = j
            continue
        out.append(src[i])
        i += 1
    return ''.join(out)


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else 'formal'
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != '.lake']
        for fn in filenames:
            if not fn.endswith('.lean'):
                continue
            path = os.path.join(dirpath, fn)
            try:
                src = io.open(path, encoding='utf-8').read()
            except (IOError, UnicodeDecodeError) as exc:
                print('SKIP %s (%s)' % (path, exc))
                continue
            stripped = strip_comments(src)
            for lineno, line in enumerate(stripped.split('\n'), 1):
                m = TOKENS.search(line)
                if m:
                    real = src.split('\n')[lineno - 1].strip()
                    hits.append((path.replace('\\', '/'), lineno, m.group(1), real))

    if hits:
        print('REAL sorry/admit found -- a theorem with sorry is an assumption, not a result:')
        for path, lineno, tok, line in hits:
            print('  %s:%d  [%s]  %s' % (path, lineno, tok, line))
        print('')
        print('%d occurrence(s).' % len(hits))
        return 1

    print('OK: no sorry/admit in Lean code (comments mentioning them are ignored).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
