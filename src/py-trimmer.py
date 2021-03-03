import io
import os
import sys
import token
import tokenize


def trim(source, mod):
    prev_pdoc = False
    prev_ttext = ''
    prev_toktype = token.NEWLINE
    seen_content = True
    last_printed_slineno = 1
    prev_slineno = -1
    prev_elineno = -1
    prev_ecol = 0
    indent_lvl = 0

    tokgen = tokenize.generate_tokens(source.readline)
    for toktype, ttext, (slineno, scol), (elineno, ecol), ltext in tokgen:
        # print('%10s %-14s %-20r %r' % (
        #     tokenize.tok_name.get(toktype, toktype),
        #     '{slineno}.{scol}-{elineno}.{ecol}',
        #     ttext, ltext
        #     ))
        if slineno > prev_elineno:
            prev_ecol = 0
            if prev_toktype not in (token.NL, token.NEWLINE):
                mod.write('\\')
                prev_toktype = token.NL
        if toktype == token.NL and prev_toktype in (
                token.NEWLINE, tokenize.COMMENT):
            toktype = token.NEWLINE

        print_token = False
        pdoc = False

        if prev_pdoc:
            if toktype == token.NEWLINE:
                # Docstring
                pass
            elif toktype == token.STRING:
                # Docstring continuation
                slineno = prev_slineno
                ttext = prev_ttext + ttext
                pdoc = True
            else:
                # Not docstring
                slineno = prev_slineno
                ttext = prev_ttext + ttext

        if toktype == token.STRING and prev_toktype in (
                token.INDENT, token.NEWLINE):
            # Possible Docstring
            pdoc = True
        elif toktype == tokenize.COMMENT:
            # Comment
            pass
        elif toktype == tokenize.INDENT:
            indent_lvl += 1
            ecol = prev_ecol
            seen_content = False
        elif toktype == tokenize.DEDENT:
            if not seen_content:
                # Removal of docstring causes empty block, needs `pass`
                if slineno > last_printed_slineno:
                    mod.write('\n')
                    last_printed_slineno += 1
                mod.write(' ' * indent_lvl)
                mod.write('pass')

                seen_content = True
            indent_lvl -= 1
            ecol = prev_ecol
        elif toktype in (token.NL, token.NEWLINE):
            pass
        else:
            print_token = True
            seen_content = True

        if print_token:
            if slineno > last_printed_slineno:
                mod.write('\n' * (slineno - last_printed_slineno))
                last_printed_slineno = slineno

            if scol > prev_ecol:
                # Space
                if prev_toktype == token.NL:
                    # Unnecessary indent for continuation
                    pass
                elif prev_toktype in (token.NEWLINE, tokenize.INDENT,
                                      tokenize.DEDENT):
                    mod.write(' ' * indent_lvl)

                namelike = (token.NAME, token.NUMBER, token.STRING)
                if prev_toktype in namelike and toktype in namelike:
                    # Necessary space between names
                    mod.write(' ')

            elif prev_pdoc:
                mod.write(' ' * indent_lvl)

            mod.write(ttext)
            last_printed_slineno += ttext.count('\n')

        prev_pdoc = pdoc
        prev_ttext = ttext
        prev_toktype = toktype
        prev_ecol = ecol
        prev_slineno = slineno
        prev_elineno = elineno


def do_file(path):
    mod = io.StringIO()
    with open(path, 'r') as source:
        trim(source, mod)

    with open(path, 'w') as out:
        out.write(mod.getvalue())


if os.path.isdir(sys.argv[1]):
    for root, dirs, files in os.walk(sys.argv[1]):
        for name in files:
            if name.endswith('.py'):
                do_file(os.path.join(root, name))
else:
    do_file(sys.argv[1])
