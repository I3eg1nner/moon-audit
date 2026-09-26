"""Fixed literate source probes; construction does not invoke any tool."""
BAD = 'fn f() -> Int { unknown_name }'

def base_cases():
    CASES = {}

    def case(n, op, cl='```', body=BAD):
        CASES[n] = '# Heading\n\n' + op + '\n' + body + '\n' + cl + '\n'
    for info in ['mbt', 'mbt check', 'mbt nocheck', 'moonbit', 'moonbit check', 'mbt test', 'mbt-check', 'mbt  check', 'mbt\tcheck', ' mbt check', 'mbt check ', 'mbt check extra', 'MBT check', '']:
        case('info_' + repr(info), '```' + info)
    for n in [1, 2, 3, 4, 5, 6]:
        case('ticks_' + str(n), '`' * n + 'mbt check', '`' * n)
    case('tilde', '~~~mbt check', '~~~')
    for n in [1, 2, 3, 4, 8]:
        case('indent_' + str(n), ' ' * n + '```mbt check', ' ' * n + '```', ' ' * n + BAD)
        case('indent_op_only_' + str(n), ' ' * n + '```mbt check', '```', BAD)
    for p in ['\t', '> ', '- ', '  - ']:
        case('prefix_' + repr(p), p + '```mbt check', p + '```', p + BAD)
    case('inline', 'text ```mbt check')
    case('unclosed', '```mbt check', '')
    case('close_extra', '```mbt check', '``` stuff')
    case('close_more', '```mbt check', '````')
    case('close_less', '````mbt check', '```')
    case('close_indent', '```mbt check', '   ```')
    case('body_indent', '```mbt check', '```', '    ' + BAD)
    case('unicode_before', '```mbt check', '```', 'fn f() -> String { let x = "月"; unknown_name }')
    case('invalid', '```mbt check', '```', 'fn f() -> Int { $ }')
    case('frontmatter', '```mbt check')
    CASES['frontmatter'] = '---\nname: test\n---\n' + CASES['frontmatter']
    case('crlf', '```mbt check')
    CASES['crlf'] = CASES['crlf'].replace('\n', '\r\n')
    CASES['split_decl'] = '```mbt check\nfn f() -> Int {\n```\n\n```mbt check\nunknown_name }\n```\n'
    CASES['shared_decl'] = '```mbt check\nfn f() -> Int { 1 }\n```\n\n```mbt check\nfn g() -> Int { f() }\n```\n'
    CASES['mbt_and_check'] = '```mbt\nfn f() -> Int { 1 }\n```\n\n```mbt check\nfn g() -> Int { f() }\n```\n'
    CASES['nested'] = '```text\n```mbt check\n' + BAD + '\n```\n```\n'
    CASES['empty_then_bad'] = '```mbt check\n```\n```mbt check\n' + BAD + '\n```\n'
    return CASES

def extended_cases():

    def case(n, op, cl='```', body=BAD):
        CASES[n] = '# Heading\n\n' + op + '\n' + body + '\n' + cl + '\n'
    base = base_cases()
    CASES = {}
    for (name, src) in base.items():
        if not name.startswith('info_'):
            CASES['bare_' + name] = src.replace('mbt check', 'mbt')
    for info in ['mbt test', 'mbt test extra', 'mbt check nocheck', 'mbt nocheck check', 'mbt check,', 'mbt xcheck', 'mbt checks', 'mbt testx', 'mbt skip', 'mbt ignore', 'mbt norun', 'mbt +check', 'mbt check\t', 'mbt    test', 'moonbit test', 'mbt test,', 'mbt,test', 'mbt,check', 'mbt{check}']:
        case('flag_' + repr(info), '```' + info)
    for (name, src) in {'list': '- ```mbt check\n  ' + BAD + '\n  ```\n', 'ordered': '1. ```mbt check\n   ' + BAD + '\n   ```\n', 'quote_lazy': '> ```mbt check\n' + BAD + '\n```\n', 'quote_double': '> > ```mbt check\n> > ' + BAD + '\n> > ```\n', 'frontmatter_bare': '---\n```mbt\n' + BAD + '\n```\n---\n', 'frontmatter_check': '---\n```mbt check\n' + BAD + '\n```\n---\n', 'html': '<!--\n```mbt check\n' + BAD + '\n```\n-->\n', 'block_comment': '```mbt check\n/*\n```\n```mbt check\n*/\n' + BAD + '\n```\n'}.items():
        CASES[name] = src
    return CASES
