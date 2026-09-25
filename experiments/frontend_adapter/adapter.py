"""Fail-closed MoonBit AST -> independent core IR experiment.

Analyzer toolchain is pinned; the target project uses its own compiler.
Only single-file, compiled, non-generic direct calls and String fields.
The two source/sink names below are explicit fixture models, not inferred effects.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

CORE = Path(__file__).resolve().parents[1] / 'core_semantics'
sys.path.insert(0, str(CORE))
from engine import ContractError, Program, Solver  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
ANALYZER_MOON = 'moon 0.1.20260920'
ANALYZER_COMPILER = 'moonc v0.10.14+7d59c7ec9'
SUPPORTED_PARSER = 'moonbitlang/parser@0.4.0'


class Reject(Exception):
    def __init__(self, status: str, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def run(command, cwd, *, timeout=60):
    try:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                                encoding='utf-8', timeout=timeout)
    except FileNotFoundError as error:
        raise Reject('tool_unavailable', str(error)) from error
    except subprocess.TimeoutExpired as error:
        raise Reject('tool_timeout', str(error)) from error
    if result.returncode:
        raise Reject('tool_error', f'{command!r}: {result.stderr or result.stdout}')
    return result.stdout


def node(value, kind):
    if not isinstance(value, dict) or value.get('kind') != kind:
        raise Reject('unsupported_syntax', f'expected {kind}; got {value.get("kind") if isinstance(value, dict) else type(value).__name__}')
    return value['children']


def child(value, kind):
    return node(value, kind)


def items(value, kind):
    data = node(value, kind)
    if not isinstance(data, list):
        raise Reject('ast_contract_changed', f'{kind} children are not a list')
    return data


def name(value, kind):
    return node(value, kind)['value']


def ident(expr):
    data = node(expr, 'Expr::Ident')
    var = node(data['id'], 'Var')
    return name(var['name'], 'LongIdent::Ident')


def type_name(value):
    data = node(value, 'Type::Name')
    if items(data['tys'], 'Type::Name::TypeList'):
        raise Reject('unsupported_semantics', 'generic type')
    constr = node(data['constr_id'], 'ConstrId')
    return name(constr['id'], 'LongIdent::Ident')


def location(node_value):
    loc = node_value.get('loc')
    if not isinstance(loc, dict) or 'start' not in loc:
        raise Reject('ast_contract_changed', 'source location missing')
    return loc['start']['line'], loc['start']['column']


def site(prefix, value):
    line, col = location(value)
    return f'{prefix}@{line}:{col}'


class Lowerer:
    def __init__(self, ast, source_path: Path, project: Path, project_moon):
        self.ast, self.source_path, self.project, self.project_moon = ast, source_path, project, project_moon
        self.declarations, self.layouts = {}, {}
        self.bindings, self.functions = {}, {}
        self.lookups = []
        self.counter = 0
        self.scan_declarations()

    def fresh(self, prefix):
        self.counter += 1
        return f'{prefix}_{self.counter}'

    def scan_declarations(self):
        for top in self.ast:
            kind = top.get('kind')
            if kind == 'Impl::TopTypeDef':
                decl = node(node(top, kind)['value'], 'TypeDecl')
                ty = decl['tycon']
                if self.layouts or ty != 'Box' or items(decl['params'], 'TypeDecl::ParamList'):
                    raise Reject('unsupported_semantics', 'only one non-generic Box record')
                rec = node(decl['components'], 'TypeDesc::Record')
                fields = items(rec['value'], 'TypeDesc::Record::FieldList')
                layout = {}
                for field in fields:
                    fd = node(field, 'FieldDecl')
                    label = node(fd['name'], 'FieldName')['label']
                    if type_name(fd['ty']) != 'String' or label in layout:
                        raise Reject('unsupported_semantics', 'Box fields must be unique String fields')
                    layout[label] = bool(fd['mut'])
                self.layouts[ty] = layout
            elif kind == 'Impl::TopFuncDef':
                data = node(top, kind)
                fun = node(data['fun_decl'], 'FunDecl')
                if fun['type_name'] is not None or fun['is_async'] is not None or fun['has_error'] is not None or data['where_clause'] is not None:
                    raise Reject('unsupported_semantics', 'method, async, error or where clause')
                if items(fun['quantifiers'], 'FunDecl::QuantifierList') or items(fun['attrs'], 'FunDecl::AttrList'):
                    raise Reject('unsupported_semantics', 'generic function or attributes')
                node(fun['error_type'], 'ErrorType::NoErrorType')
                label = node(fun['name'], 'Binder')['name']
                if label in self.declarations:
                    raise Reject('unsupported_semantics', f'duplicate function: {label}')
                params = []
                for param in items(fun['decl_params'], 'FunDecl::ParameterList'):
                    p = node(param, 'Parameter::Positional')
                    if p['ty'] is None:
                        raise Reject('unsupported_semantics', 'parameter needs explicit type')
                    params.append((node(p['binder'], 'Binder')['name'], type_name(p['ty'])))
                decl_line, decl_col = location(fun['name'])
                fid = f'main.mbt:{decl_line}:{decl_col}:{label}'
                if fun['return_type'] is None:
                    raise Reject('unsupported_semantics', 'function needs explicit return type')
                self.declarations[label] = {'fid': fid, 'name_node': fun['name'],
                                            'params': params, 'return': type_name(fun['return_type']),
                                            'body': node(data['decl_body'], 'DeclBody::DeclBody')['expr']}
            else:
                raise Reject('unsupported_syntax', f'top-level {kind}')
        if 'go' not in self.declarations:
            raise Reject('unsupported_semantics', 'go is required')
        for label, params, result in [('source', [], 'String'), ('sink', [('value', 'String')], 'Unit')]:
            decl = self.declarations.get(label)
            if decl is None or decl['params'] != params or decl['return'] != result:
                raise Reject('model_mismatch', f'fixture model signature changed: {label}')
        node(self.declarations['source']['body'], 'Expr::Constant')
        if node(self.declarations['source']['body'], 'Expr::Constant')['constant']['kind'] != 'Constant::String':
            raise Reject('model_mismatch', 'source body changed')
        sink_body = node(self.declarations['sink']['body'], 'Expr::Apply')
        sink_args = items(sink_body['args'], 'Expr::Apply::ArgumentList')
        if (ident(sink_body['func']) != 'ignore' or len(sink_args) != 1
                or node(sink_args[0], 'Argument')['kind']['kind'] != 'ArgumentKind::Positional'
                or ident(node(sink_args[0], 'Argument')['value']) != 'value'):
            raise Reject('model_mismatch', 'sink body changed')

    def verify_call(self, func_node, label):
        line, col = location(func_node)
        query = [*self.project_moon, 'ide', 'peek-def', '--json', '--no-check', '--target', 'native',
                 '--loc', f'main.mbt:{line}:{col}']
        output = run(query, self.project)
        try:
            found = json.loads(output)
        except ValueError as error:
            raise Reject('binding_unavailable', f'IDE JSON: {error}') from error
        decl = self.declarations[label]
        expected_line, expected_col = location(decl['name_node'])
        expected_range = f'{expected_line}:{expected_col}-'
        if len(found) != 1 or Path(found[0].get('path', '')).resolve() != self.source_path.resolve() or not found[0].get('range', '').startswith(expected_range):
            raise Reject('binding_unavailable', f'{label}@{line}:{col} resolved to {found}, expected {expected_range}')
        self.lookups.append({'call': f'{label}@{line}:{col}',
                             'declaration': {'path': 'main.mbt', 'range': found[0]['range']}})

    def lower(self):
        for label, decl in self.declarations.items():
            if label in {'source', 'sink'}:
                continue
            if decl['return'] not in {'Unit', 'String'} or any(ty not in {'Box', 'String'} for _, ty in decl['params']):
                raise Reject('unsupported_semantics', f'{label}: only Unit/String return and explicit Box/String params')
            if not self.layouts and any(ty == 'Box' for _, ty in decl['params']):
                raise Reject('unsupported_semantics', f'{label}: Box parameter requires its declaration')
            if self.layouts and decl['return'] == 'String':
                raise Reject('unsupported_semantics', f'{label}: String return is only verified in the no-heap profile')
            self.current, self.blocks, self.block = label, {'entry': []}, 'entry'
            env = {}
            params = []
            for index, (param, _) in enumerate(decl['params']):
                reg = f'param_{index}'
                env[param] = reg
                params.append(reg)
            value = self.evaluate(decl['body'], env)
            if decl['return'] == 'Unit':
                value = self.fresh('unit')
                self.emit({'op': 'clean', 'out': value})
            self.emit({'op': 'return', 'value': value})
            self.functions[decl['fid']] = {'params': params, 'entry': 'entry', 'blocks': self.blocks}
        if self.declarations['go']['params']:
            raise Reject('unsupported_semantics', 'go needs zero arguments')
        return {'entry': self.declarations['go']['fid'], 'functions': self.functions, 'bindings': self.bindings}

    def emit(self, op):
        self.blocks[self.block].append(op)

    def evaluate(self, expr, env):
        kind = expr.get('kind')
        data = expr.get('children', {})
        if kind == 'Expr::Sequence':
            for part in items(data['exprs'], 'Expr::Sequence::ExprList'):
                self.evaluate(part, env)
            return self.evaluate(data['last_expr'], env)
        if kind == 'Expr::Let':
            binder = node(data['pattern'], 'Pattern::Var')['value']
            label = node(binder, 'Binder')['name']
            initial = self.evaluate(data['expr'], env)
            scoped = dict(env)
            scoped[label] = initial
            return self.evaluate(data['body'], scoped)
        if kind == 'Expr::Ident':
            label = ident(expr)
            if label not in env:
                raise Reject('unsupported_semantics', f'non-local value {label}')
            return env[label]
        if kind == 'Expr::Constant':
            node(data['constant'], 'Constant::String')
            out = self.fresh('literal')
            self.emit({'op': 'clean', 'out': out})
            return out
        if kind == 'Expr::Record':
            type_node = node(data['type_name'], 'TypeName')
            ty = name(type_node['name'], 'LongIdent::Ident')
            if ty != 'Box' or type_node['is_object'] or node(data['trailing'], 'Trailing::None') != {}:
                raise Reject('unsupported_semantics', 'record shape')
            fields = {}
            for field in items(data['fields'], 'Expr::Record::FieldList'):
                fd = node(field, 'FieldDef')
                if fd['is_pun']:
                    raise Reject('unsupported_semantics', 'record field pun')
                label = node(fd['label'], 'Label')['name']
                if label in fields:
                    raise Reject('unsupported_semantics', 'duplicate initializer')
                fields[label] = self.evaluate(fd['expr'], env)
            if set(fields) != set(self.layouts['Box']):
                raise Reject('unsupported_semantics', 'incomplete Box initializer')
            out = self.fresh('box')
            self.emit({'op': 'alloc', 'site': site('alloc', expr), 'out': out, 'fields': fields})
            return out
        if kind == 'Expr::Field':
            obj = self.evaluate(data['record'], env)
            field = node(node(data['accessor'], 'Accessor::Label')['value'], 'Label')['name']
            if field not in self.layouts['Box']:
                raise Reject('unsupported_semantics', f'unknown field {field}')
            out = self.fresh('field')
            self.emit({'op': 'load', 'out': out, 'object': obj, 'field': field})
            return out
        if kind == 'Expr::Mutate':
            if data['augmented_by'] is not None:
                raise Reject('unsupported_semantics', 'augmented assignment')
            obj = self.evaluate(data['record'], env)
            value = self.evaluate(data['field'], env)
            field = node(node(data['accessor'], 'Accessor::Label')['value'], 'Label')['name']
            if field not in self.layouts['Box']:
                raise Reject('unsupported_semantics', f'unknown field {field}')
            if not self.layouts['Box'][field]:
                raise Reject('unsupported_semantics', f'write to immutable field {field}')
            self.emit({'op': 'store', 'object': obj, 'field': field, 'value': value})
            out = self.fresh('unit')
            self.emit({'op': 'clean', 'out': out})
            return out
        if kind == 'Expr::Apply':
            node(data['attr'], 'ApplyAttr::NoAttr')
            label = ident(data['func'])
            if label not in self.declarations:
                raise Reject('unsupported_semantics', f'unknown direct call: {label}')
            args = []
            for arg in items(data['args'], 'Expr::Apply::ArgumentList'):
                argument = node(arg, 'Argument')
                node(argument['kind'], 'ArgumentKind::Positional')
                args.append(self.evaluate(argument['value'], env))
            decl = self.declarations[label]
            if len(args) != len(decl['params']):
                raise Reject('unsupported_semantics', f'arity mismatch: {label}')
            self.verify_call(data['func'], label)
            out = self.fresh('call')
            if label == 'source':
                self.emit({'op': 'source', 'id': site('source', expr), 'out': out})
            elif label == 'sink':
                self.emit({'op': 'sink', 'id': site('sink', expr), 'value': args[0]})
                self.emit({'op': 'clean', 'out': out})
            else:
                callsite = site('call', expr)
                next_block = self.fresh('after')
                self.bindings[callsite] = {'callee': decl['fid'],
                    'actuals': {f'param_{i}': arg for i, arg in enumerate(args)}}
                self.emit({'op': 'invoke', 'site': callsite, 'out': out, 'normal': next_block})
                self.blocks[next_block] = []
                self.block = next_block
            return out
        raise Reject('unsupported_syntax', f'expression {kind} at {expr.get("loc")}')


def _analyze(source: str, analyzer_moon: list[str], *, project_moon: list[str], fixture='input'):
    analyzer_version = run([*analyzer_moon, 'version', '--all'], ROOT)
    if ANALYZER_MOON not in analyzer_version or ANALYZER_COMPILER not in analyzer_version:
        raise Reject('analyzer_toolchain_mismatch', analyzer_version.strip())
    project_version = run([*project_moon, 'version', '--all'], ROOT)
    if SUPPORTED_PARSER not in (ROOT / 'moon.mod').read_text():
        raise Reject('parser_dependency_mismatch', f'expected {SUPPORTED_PARSER} in moon.mod')
    with tempfile.TemporaryDirectory(prefix='moon-audit-frontend-') as directory:
        project = Path(directory)
        (project / 'moon.mod').write_text('name = "review/frontend_adapter"\npreferred_target = "native"\n')
        (project / 'moon.pkg').write_text('')
        source_path = project / 'main.mbt'
        source_path.write_text(source)
        digest = hashlib.sha256(source.encode()).hexdigest()
        try:
            run([*project_moon, 'check', '--target', 'native'], project)
        except Reject as error:
            raise Reject('compiler_rejected', error.detail) from error
        export_cmd = [*analyzer_moon, 'run', '--target', 'native', 'src/frontend_export', str(source_path)]
        exported = subprocess.run(export_cmd, cwd=ROOT, capture_output=True, text=True, timeout=60)
        if exported.returncode:
            status = 'parser_rejected' if exported.returncode == 3 else 'tool_error'
            raise Reject(status, exported.stdout or exported.stderr)
        output = exported.stdout
        try:
            ast = json.loads(output)
        except ValueError as error:
            raise Reject('ast_contract_changed', str(error)) from error
        lowerer = Lowerer(ast, source_path, project, project_moon)
        document = lowerer.lower()
        if hashlib.sha256(source_path.read_bytes()).hexdigest() != digest:
            raise Reject('source_changed', 'source changed after compiler check')
        result = Solver(Program(document)).run().report()
        return {'schema': 'moon-audit.frontend-adapter.v1', 'fixture': fixture,
                'status': result['status'], 'analyzer_toolchain': analyzer_version.strip(),
                'project_toolchain': project_version.strip(), 'parser_package': SUPPORTED_PARSER,
                'source_sha256': digest, 'target': 'native',
                'ast_schema': sorted({f"{n['kind']}|{','.join(sorted(n['children'])) if isinstance(n.get('children'), dict) else '[]'}" for n in walk_ast(ast)}),
                'lookups': lowerer.lookups, 'ir': document, 'result': result}


def analyze(source: str, analyzer_moon: list[str], *, project_moon: list[str] | None = None, fixture='input'):
    try:
        return _analyze(source, analyzer_moon, project_moon=project_moon or analyzer_moon, fixture=fixture)
    except (KeyError, TypeError, IndexError) as error:
        raise Reject('ast_contract_changed', str(error)) from error
    except ContractError as error:
        raise Reject('ir_contract_error', str(error)) from error
    except subprocess.TimeoutExpired as error:
        raise Reject('tool_timeout', str(error)) from error
    except OSError as error:
        raise Reject('tool_unavailable', str(error)) from error

def walk_ast(value):
    if isinstance(value, dict):
        if isinstance(value.get('kind'), str):
            yield value
        for child_value in value.values():
            yield from walk_ast(child_value)
    elif isinstance(value, list):
        for child_value in value:
            yield from walk_ast(child_value)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', type=Path)
    parser.add_argument('--analyzer-moon-wrapper', type=Path, help='wrapper for the version used to build this analyzer')
    parser.add_argument('--project-moon-wrapper', type=Path, help='wrapper for the target project toolchain')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    analyzer_moon = [str(args.analyzer_moon_wrapper), 'moon'] if args.analyzer_moon_wrapper else ['moon']
    project_moon = [str(args.project_moon_wrapper), 'moon'] if args.project_moon_wrapper else analyzer_moon
    try:
        output = analyze(args.file.read_text(), analyzer_moon, project_moon=project_moon, fixture=args.file.name)
        code = 0 if output['status'] == 'fixed_point' else 2
    except Reject as error:
        output = {'schema': 'moon-audit.frontend-adapter.v1', 'status': error.status, 'detail': error.detail}
        code = 2
    rendered = json.dumps(output, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.write_text(rendered)
    else:
        print(rendered, end='')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
