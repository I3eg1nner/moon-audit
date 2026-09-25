"""Executable semantic specification, intentionally independent of the AST scanner.

Finite values + allocation/context identities + input-state tabulation. The same
heap is used by loads, stores, calls, returns and exceptions. No AST fallback.
"""
from __future__ import annotations

from collections import deque
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import time
from types import MappingProxyType


class ContractError(ValueError):
    pass


class BudgetExceeded(Exception):
    pass


ObjectId = tuple[str, str]  # explicit allocation site, immediately enclosing call site


@dataclass(frozen=True)
class Value:
    sources: frozenset[str] = frozenset()
    refs: frozenset[ObjectId] = frozenset()
    booleans: frozenset[bool] = frozenset()

    def join(self, other):
        return Value(self.sources | other.sources, self.refs | other.refs,
                     self.booleans | other.booleans)


CLEAN = Value()


@dataclass(frozen=True)
class Object:
    fields: tuple[tuple[str, Value], ...]
    many: bool = False


@dataclass(frozen=True)
class Heap:
    objects: tuple[tuple[ObjectId, Object], ...] = ()

    def allocate(self, oid, fields):
        objects = dict(self.objects)
        previous = objects.get(oid)
        if previous:
            fields = {k: v.join(dict(previous.fields).get(k, CLEAN)) for k, v in fields.items()}
        objects[oid] = Object(tuple(sorted(fields.items())), previous is not None)
        return Heap(tuple(sorted(objects.items())))

    def load(self, refs, field):
        if not refs:
            raise ContractError("load requires an object reference")
        objects, result = dict(self.objects), CLEAN
        for oid in refs:
            obj = objects.get(oid)
            if obj is None or field not in dict(obj.fields):
                raise ContractError(f"unknown object/field: {oid}.{field}")
            result = result.join(dict(obj.fields)[field])
        return result

    def store(self, refs, field, value):
        if not refs:
            raise ContractError("store requires an object reference")
        objects = dict(self.objects)
        for oid in refs:
            obj = objects.get(oid)
            if obj is None or field not in dict(obj.fields):
                raise ContractError(f"unknown object/field: {oid}.{field}")
            fields = dict(obj.fields)
            fields[field] = value if len(refs) == 1 and not obj.many else fields[field].join(value)
            objects[oid] = Object(tuple(sorted(fields.items())), obj.many)
        return Heap(tuple(sorted(objects.items())))

    def join(self, other):
        objects = dict(self.objects)
        for oid, right in other.objects:
            left = objects.get(oid)
            if left is None:
                objects[oid] = right
                continue
            lfields, rfields = dict(left.fields), dict(right.fields)
            if lfields.keys() != rfields.keys():
                raise ContractError("one allocation identity cannot have two layouts")
            objects[oid] = Object(tuple(sorted((k, v.join(rfields[k])) for k, v in lfields.items())),
                                  left.many or right.many)
        return Heap(tuple(sorted(objects.items())))


@dataclass(frozen=True)
class State:
    registers: tuple[tuple[str, Value], ...]
    heap: Heap

    def read(self, reg):
        try:
            return dict(self.registers)[reg]
        except KeyError as e:
            raise ContractError(f"undefined register {reg}") from e

    def bind(self, reg, value, heap=None):
        registers = dict(self.registers)
        registers[reg] = value
        return State(tuple(sorted(registers.items())), self.heap if heap is None else heap)

    def join(self, other):
        left, right = dict(self.registers), dict(other.registers)
        # A value defined on only one predecessor is not available after join.
        registers = tuple(sorted((k, v.join(right[k])) for k, v in left.items() if k in right))
        return State(registers, self.heap.join(other.heap))


@dataclass(frozen=True)
class Exit:
    value: Value
    heap: Heap

    def join(self, other):
        return Exit(self.value.join(other.value), self.heap.join(other.heap))


@dataclass(frozen=True)
class Invocation:
    function: str
    context: str
    actuals: tuple[Value, ...]
    heap: Heap


def freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(freeze(item) for item in value)
    return value


class Program:
    TERMINATORS = {"branch", "jump", "invoke", "return", "raise"}
    OPS = TERMINATORS | {"clean", "source", "bool", "copy", "alloc", "load", "store", "sink"}

    def __init__(self, document):
        self.document = deepcopy(document)
        self.functions = self.document["functions"]
        self.bindings = self.document.get("bindings", {})
        self.entry = self.document["entry"]
        self.allocation_sites, self.fields, self.sources, self.sinks = set(), set(), set(), set()
        self.validate()
        canonical = json.dumps(self.document, sort_keys=True, separators=(",", ":"))
        self.digest = hashlib.sha256(canonical.encode()).hexdigest()
        self.document = freeze(self.document)
        self.functions = self.document["functions"]
        self.bindings = self.document.get("bindings", MappingProxyType({}))
        self.allocation_sites = frozenset(self.allocation_sites)
        self.fields, self.sources, self.sinks = frozenset(self.fields), frozenset(self.sources), frozenset(self.sinks)
        contexts = {"$entry", *self.bindings}
        self.object_universe = frozenset((site, context) for site in self.allocation_sites for context in contexts)
        self.top = Value(frozenset({"*", *self.sources}), self.object_universe, frozenset({False, True}))

    def validate(self):
        if self.entry not in self.functions:
            raise ContractError("entry is undefined")
        sites = set()
        for fid, function in self.functions.items():
            params, blocks = function["params"], function["blocks"]
            if len(set(params)) != len(params) or function["entry"] not in blocks:
                raise ContractError(f"invalid declaration: {fid}")
            for bid, ops in blocks.items():
                if not ops or ops[-1].get("op") not in self.TERMINATORS:
                    raise ContractError(f"unterminated block: {fid}/{bid}")
                for i, op in enumerate(ops):
                    kind = op.get("op")
                    if kind not in self.OPS:
                        raise ContractError(f"unsupported opcode: {kind}")
                    if kind in self.TERMINATORS and i != len(ops) - 1:
                        raise ContractError("instructions after a terminator")
                    if kind == "alloc":
                        if op["site"] in self.allocation_sites:
                            raise ContractError("allocation sites must be globally unique")
                        self.allocation_sites.add(op["site"])
                        self.fields.update(op["fields"])
                    if kind in ("source", "sink"):
                        collection = self.sources if kind == "source" else self.sinks
                        if op["id"] in collection:
                            raise ContractError(f"duplicate {kind} identity")
                        collection.add(op["id"])
                    if kind == "bool" and op["value"] is not None and not isinstance(op["value"], bool):
                        raise ContractError("invalid boolean constant")
                    destinations = []
                    if kind == "jump":
                        destinations = [op["target"]]
                    if kind == "branch":
                        destinations = [op["yes"], op["no"]]
                    if kind == "invoke":
                        site = op["site"]
                        if site in sites or site not in self.bindings:
                            raise ContractError("invoke needs one unique binding row")
                        sites.add(site)
                        binding = self.bindings[site]
                        target = self.functions.get(binding["callee"])
                        if target is None or set(binding["actuals"]) != set(target["params"]):
                            raise ContractError("binding must name every formal of one defined callee")
                        destinations = [op["normal"], *op.get("catch", {}).values()]
                    if any(destination not in blocks for destination in destinations):
                        raise ContractError("undefined successor")
        if sites != set(self.bindings):
            raise ContractError("orphan call binding")


@dataclass
class Result:
    status: str
    exits: dict[str, Exit]
    findings: dict[str, Value]
    stats: dict
    program_digest: str
    cache_hit: bool = False

    def report(self):
        return {
            "status": self.status,
            "program_digest": self.program_digest,
            "findings": {site: sorted(value.sources) for site, value in sorted(self.findings.items())},
            "exits": sorted(self.exits),
            "stats": self.stats,
            "cache_hit": self.cache_hit,
        }


class Solver:
    """Finite input-state tabulation, with dependency-triggered re-evaluation.

    Input aliases and heap values belong to the invocation key. There is no
    symbolic formal-field substitution and no second heap in a consumer.
    """
    def __init__(self, program, *, max_steps=100_000, max_invocations=2_000, max_seconds=10.0):
        self.program = program
        self.max_steps, self.max_invocations = max_steps, max_invocations
        self.max_seconds = max_seconds
        self.deadline = float("inf")
        self.entries, self.dependents, self.nodes = {}, {}, {}
        self.queue, self.queued = deque(), set()
        self.findings = {}
        self.steps = self.evaluations = self.peak_queue = 0

    def enqueue(self, key):
        if key not in self.queued:
            self.queued.add(key)
            self.queue.append(key)
            self.peak_queue = max(self.peak_queue, len(self.queue))

    def push_state(self, key, block, state):
        node = (key, block)
        previous = self.nodes.get(node)
        merged = previous.join(state) if previous else state
        if merged != previous:
            self.nodes[node] = merged
            self.enqueue(node)

    def require(self, key, caller=None):
        if key not in self.entries:
            if len(self.entries) >= self.max_invocations:
                raise BudgetExceeded("invocation budget")
            self.entries[key] = {}
            function = self.program.functions[key.function]
            registers = tuple(sorted(zip(function["params"], key.actuals)))
            self.push_state(key, function["entry"], State(registers, key.heap))
        if caller is not None:
            self.dependents.setdefault(key, set()).add(caller)
        return self.entries[key]

    def step(self):
        self.steps += 1
        if time.monotonic() >= self.deadline:
            raise BudgetExceeded("wall time budget")
        if self.steps > self.max_steps:
            raise BudgetExceeded("transfer budget")

    def evaluate(self, node):
        self.evaluations += 1
        key, block = node
        function = self.program.functions[key.function]
        state = self.nodes[node]

        def emit(tag, value, heap):
            previous = self.entries[key].get(tag)
            exit = Exit(value, heap)
            merged = previous.join(exit) if previous else exit
            if merged != previous:
                self.entries[key][tag] = merged
                for dependent in sorted(self.dependents.get(key, ()), key=repr):
                    self.enqueue(dependent)

        def push(block, state):
            self.push_state(key, block, state)

        for op in function["blocks"][block]:
            self.step()
            kind = op["op"]
            if kind == "clean":
                state = state.bind(op["out"], CLEAN)
            elif kind == "source":
                state = state.bind(op["out"], Value(frozenset({op["id"]})))
            elif kind == "bool":
                options = {False, True} if op["value"] is None else {op["value"]}
                state = state.bind(op["out"], Value(booleans=frozenset(options)))
            elif kind == "copy":
                state = state.bind(op["out"], state.read(op["value"]))
            elif kind == "alloc":
                oid = (op["site"], key.context)
                heap = state.heap.allocate(oid, {f: state.read(v) for f, v in op["fields"].items()})
                state = state.bind(op["out"], Value(refs=frozenset({oid})), heap)
            elif kind == "load":
                value = state.heap.load(state.read(op["object"]).refs, op["field"])
                state = state.bind(op["out"], value)
            elif kind == "store":
                heap = state.heap.store(state.read(op["object"]).refs, op["field"], state.read(op["value"]))
                state = State(state.registers, heap)
            elif kind == "sink":
                value = state.read(op["value"])
                if value.sources:
                    self.findings[op["id"]] = self.findings.get(op["id"], CLEAN).join(value)
            elif kind == "jump":
                push(op["target"], state)
            elif kind == "branch":
                options = state.read(op["condition"]).booleans
                if not options:
                    raise ContractError("branch requires a boolean")
                for option, target in ((True, op["yes"]), (False, op["no"])):
                    if option in options:
                        push(target, state)
            elif kind == "invoke":
                binding = self.program.bindings[op["site"]]
                callee = self.program.functions[binding["callee"]]
                actuals = tuple(state.read(binding["actuals"][p]) for p in callee["params"])
                target = Invocation(binding["callee"], op["site"], actuals, state.heap)
                for tag, exit in self.require(target, node).items():
                    if tag == "$normal":
                        push(op["normal"], state.bind(op["out"], exit.value, exit.heap))
                    else:
                        handler = op.get("catch", {}).get(tag, op.get("catch", {}).get("*"))
                        if handler is None:
                            emit(tag, exit.value, exit.heap)
                        else:
                            push(handler, state.bind(op["error"], exit.value, exit.heap))
            elif kind == "return":
                emit("$normal", state.read(op["value"]), state.heap)
            elif kind == "raise":
                if op["tag"] == "$normal":
                    raise ContractError("reserved exception tag")
                emit(op["tag"], state.read(op["value"]), state.heap)

    def run(self, actuals=(), heap=Heap()):
        if len(actuals) != len(self.program.functions[self.program.entry]["params"]):
            raise ContractError("entry arity mismatch")
        if self.entries:
            raise ContractError("a solver instance represents exactly one run")
        root = Invocation(self.program.entry, "$entry", tuple(actuals), heap)
        started = time.monotonic()
        self.deadline = started + self.max_seconds
        reason = None
        try:
            self.require(root)
            while self.queue:
                node = self.queue.popleft()
                self.queued.remove(node)
                self.evaluate(node)
            status, exits = "fixed_point", self.entries[root]
        except BudgetExceeded as error:
            reason, status = str(error), "incomplete_budget"
            # Explicit whole-program top. Include future allocations and sinks:
            # unvisited effects are never returned as clean or unreachable.
            initial_objects = dict(heap.objects)
            object_ids = self.program.object_universe | initial_objects.keys()
            initial_values = list(actuals) + [v for obj in initial_objects.values() for _, v in obj.fields]
            sources = {"*", *self.program.sources}
            fields = set(self.program.fields)
            for value in initial_values:
                sources.update(value.sources)
                object_ids = object_ids | value.refs
            for obj in initial_objects.values():
                fields.update(dict(obj.fields))
            top = Value(frozenset(sources), frozenset(object_ids), frozenset({False, True}))
            all_fields = tuple((field, top) for field in sorted(fields))
            top_heap = Heap(tuple((oid, Object(all_fields, True)) for oid in sorted(object_ids)))
            exits = {"$normal": Exit(top, top_heap), "*": Exit(top, top_heap)}
            self.findings = {site: top for site in self.program.sinks}
        return Result(status, exits, self.findings, {
            "transfers": self.steps, "invocations": len(self.entries), "evaluations": self.evaluations, "state_nodes": len(self.nodes),
            "peak_queue": self.peak_queue, "seconds": round(time.monotonic() - started, 6),
            "budget_reason": reason, "max_steps": self.max_steps, "max_invocations": self.max_invocations, "max_seconds": self.max_seconds,
        }, self.program.digest)


class AnalysisCache:
    """Whole-result cache for the specification, not production incremental cache."""
    POLICY = "core-spec-v1-input-heap-callsite1"

    def __init__(self):
        self.results = {}

    def run(self, program, actuals=(), heap=Heap(), *, max_steps=100_000, max_invocations=2_000, max_seconds=10.0):
        key = (self.POLICY, program.digest, tuple(actuals), heap, max_steps, max_invocations, max_seconds)
        if key in self.results:
            result = deepcopy(self.results[key])
            result.cache_hit = True
            return result
        result = Solver(program, max_steps=max_steps, max_invocations=max_invocations, max_seconds=max_seconds).run(actuals, heap)
        if result.status == "fixed_point":
            self.results[key] = deepcopy(result)
        return result
