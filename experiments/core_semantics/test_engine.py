import random
import unittest
from copy import deepcopy

from experiments.core_semantics.engine import AnalysisCache, CLEAN, ContractError, Heap, Program, Solver, Value
from experiments.core_semantics.oracle import Concrete
from experiments.core_semantics.scenarios import alias_program, call_chain, factory_program, function, op, recursive_program, witnesses


def observed(result):
    return {site: set(value.sources) for site, value in result.findings.items()}


def concrete_union(document):
    result = {}
    # Includes base, one recursive call and two recursive calls followed by base.
    for choices in ([], [True], [True, True, False]):
        for site, sources in Concrete(document, choices).run().items():
            result.setdefault(site, set()).update(sources)
    return result


def generated_programs(seed=17, count=256):
    rng = random.Random(seed)
    for _ in range(count):
        document = alias_program(alias=rng.choice([True, False]))
        instructions = [op("source", id="helper/source", out="dirty"), op("clean", out="clean")]
        registers = ["dirty", "clean"]
        for index in range(8):
            receiver, field = rng.choice(["first", "second"]), rng.choice(["value", "safe"])
            if rng.choice([True, False]):
                instructions.append(op("store", object=receiver, field=field, value=rng.choice(registers)))
            else:
                register = f"read_{index}"
                instructions.append(op("load", object=receiver, field=field, out=register))
                registers.append(register)
        instructions.append(op("return", value=rng.choice(registers)))
        document["functions"]["demo/fill"]["blocks"]["entry"] = instructions
        yield document


class CoreSemanticsTests(unittest.TestCase):
    def test_witnesses_match_independent_concrete_traces(self):
        for name, document in witnesses().items():
            with self.subTest(witness=name):
                result = Solver(Program(document)).run()
                self.assertEqual(result.status, "fixed_point")
                self.assertEqual(observed(result), concrete_union(document))

    def test_read_after_write_alias_and_distinct_controls(self):
        same = Solver(Program(alias_program())).run()
        separate = Solver(Program(alias_program(alias=False))).run()
        self.assertEqual(set(same.findings), {"main/a.value", "main/a.safe"})
        self.assertEqual(set(separate.findings), {"main/a.value"})

    def test_order_changes_result_and_cache_key(self):
        cache = AnalysisCache()
        clean = Program(alias_program("clean_last"))
        dirty = Program(alias_program("dirty_last"))
        self.assertNotEqual(clean.digest, dirty.digest)
        cold = cache.run(clean)
        self.assertFalse(cold.findings)
        self.assertFalse(cold.cache_hit)
        warm = cache.run(clean)
        self.assertTrue(warm.cache_hit)
        self.assertEqual(cold.exits, warm.exits)
        changed = cache.run(dirty)
        self.assertFalse(changed.cache_hit)
        self.assertEqual(set(changed.findings), {"main/a.value"})
        self.assertEqual(set(cache.run(dirty).findings), {"main/a.value"})

    def test_program_snapshot_cannot_change_under_its_cache_digest(self):
        document = alias_program()
        program = Program(document)
        document["bindings"]["call/main/fill"]["actuals"]["second"] = "b"
        self.assertIn("main/a.safe", Solver(program).run().findings)
        with self.assertRaises(TypeError):
            program.bindings["call/main/fill"]["actuals"]["second"] = "b"

    def test_binding_is_consumed_and_in_cache_identity(self):
        same = alias_program()
        distinct = deepcopy(same)
        distinct["bindings"]["call/main/fill"]["actuals"]["second"] = "b"
        cache = AnalysisCache()
        self.assertIn("main/a.safe", cache.run(Program(same)).findings)
        changed = cache.run(Program(distinct))
        self.assertFalse(changed.cache_hit)
        self.assertNotIn("main/a.safe", changed.findings)

    def test_recursive_input_reaches_fixed_point_without_depth_cutoff(self):
        result = Solver(Program(recursive_program()), max_steps=1000).run()
        self.assertEqual(result.status, "fixed_point")
        self.assertEqual(observed(result), concrete_union(recursive_program()))
        self.assertEqual(result.stats["invocations"], 3)
        self.assertGreater(result.stats["evaluations"], result.stats["invocations"])
        self.assertIsNone(result.stats["budget_reason"])

    def test_budget_havocs_future_fields_exits_and_sinks(self):
        program = Program(alias_program())
        for budget in ({"max_steps": 1}, {"max_invocations": 1}, {"max_seconds": 0}):
            with self.subTest(budget=budget):
                result = Solver(program, **budget).run()
                self.assertEqual(result.status, "incomplete_budget")
                self.assertEqual(set(result.exits), {"$normal", "*"})
                self.assertEqual(set(result.findings), program.sinks)
                self.assertEqual(set(dict(result.exits["$normal"].heap.objects)), program.object_universe)
                self.assertTrue(all("*" in value.sources for value in result.findings.values()))
                for _, obj in result.exits["$normal"].heap.objects:
                    self.assertTrue(obj.many)
                    self.assertTrue(all("*" in value.sources for _, value in obj.fields))

    def test_budget_retains_supplied_objects_and_is_not_cached(self):
        document = {"entry": "demo/main", "functions": {"demo/main": function(["box"], {"entry": [
            op("load", object="box", field="value", out="v"), op("sink", id="sink", value="v"), op("return", value="v")]} )}}
        program = Program(document)
        oid = ("external/object", "$entry")
        heap = Heap().allocate(oid, {"value": Value(frozenset({"external/input"}))})
        actuals = (Value(refs=frozenset({oid})),)
        cache = AnalysisCache()
        for _ in range(2):
            result = cache.run(program, actuals, heap, max_steps=0)
            self.assertFalse(result.cache_hit)
            self.assertIn(oid, dict(result.exits["$normal"].heap.objects))
            self.assertIn("external/input", result.findings["sink"].sources)
        normal = cache.run(program, actuals, heap)
        self.assertEqual(normal.status, "fixed_point")
        self.assertEqual(observed(normal), {"sink": {"external/input"}})

    def test_repeated_allocation_identity_requires_weak_updates(self):
        oid = ("site", "call")
        dirty = Value(frozenset({"source"}))
        first = Heap().allocate(oid, {"value": dirty})
        self.assertEqual(first.store({oid}, "value", CLEAN).load({oid}, "value"), CLEAN)
        repeated = first.allocate(oid, {"value": CLEAN})
        self.assertEqual(repeated.store({oid}, "value", CLEAN).load({oid}, "value"), dirty)

    def test_factory_calls_have_distinct_contextual_objects(self):
        result = Solver(Program(factory_program())).run()
        self.assertEqual(set(result.findings), {"main/a.value"})
        objects = dict(result.exits["$normal"].heap.objects)
        self.assertEqual(set(objects), {("alloc/factory", "call/first"), ("alloc/factory", "call/second")})
        self.assertFalse(any(obj.many for obj in objects.values()))

    def test_generated_straight_line_alias_programs_match_oracle(self):
        for index, document in enumerate(generated_programs()):
            with self.subTest(program=index):
                result = Solver(Program(document)).run()
                self.assertEqual(result.status, "fixed_point")
                self.assertEqual(observed(result), Concrete(document).run())

    def test_call_chain_revisits_call_blocks_without_replaying_prefixes(self):
        for size in (8, 32, 128, 512):
            with self.subTest(calls=size):
                result = Solver(Program(call_chain(size))).run()
                self.assertEqual(result.status, "fixed_point")
                self.assertEqual(result.findings, {})
                self.assertEqual(result.stats["invocations"], size + 1)
                self.assertLessEqual(result.stats["transfers"], 4 * size + 4)

    def test_mapping_order_does_not_change_semantics(self):
        document = recursive_program()
        reversed_document = deepcopy(document)
        reversed_document["functions"] = dict(reversed(list(document["functions"].items())))
        for definition in reversed_document["functions"].values():
            definition["blocks"] = dict(reversed(list(definition["blocks"].items())))
        original, reverse = Program(document), Program(reversed_document)
        self.assertEqual(original.digest, reverse.digest)
        first, second = Solver(original).run(), Solver(reverse).run()
        self.assertEqual(first.exits, second.exits)
        self.assertEqual(first.findings, second.findings)

    def test_unsupported_or_incomplete_contracts_are_rejected(self):
        for mutation in ("fallback", "undefined_target", "missing_formal", "duplicate_site"):
            document = alias_program()
            if mutation == "fallback":
                document["functions"]["demo/fill"]["blocks"]["entry"][0]["op"] = "ast_fallback"
            elif mutation == "undefined_target":
                document["bindings"]["call/main/fill"]["callee"] = "other/fill"
            elif mutation == "missing_formal":
                del document["bindings"]["call/main/fill"]["actuals"]["second"]
            else:
                allocations = document["functions"]["demo/main"]["blocks"]["entry"]
                allocations[2]["site"] = allocations[1]["site"]
            with self.subTest(mutation=mutation), self.assertRaises(ContractError):
                Solver(Program(document)).run()


if __name__ == "__main__":
    unittest.main(verbosity=2)
