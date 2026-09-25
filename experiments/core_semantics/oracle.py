"""Independent concrete execution oracle for finite traces of the witness IR.

Uses fresh integer objects, a real call stack and concrete branch choices.
Does not import the abstract engine or reuse its heap/binding/exit evaluators.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Datum:
    sources: frozenset = frozenset()
    reference: int | None = None
    boolean: bool | None = None


class Concrete:
    def __init__(self, document, choices=(), limit=10_000):
        self.document, self.choices, self.limit = document, iter(choices), limit
        self.heap, self.findings, self.steps = {}, {}, 0

    def call(self, fid, arguments):
        function = self.document["functions"][fid]
        env, block = dict(zip(function["params"], arguments)), function["entry"]
        while True:
            for instruction in function["blocks"][block]:
                self.steps += 1
                if self.steps > self.limit:
                    raise RuntimeError("concrete trace budget exhausted")
                kind = instruction["op"]
                if kind == "clean":
                    env[instruction["out"]] = Datum()
                elif kind == "source":
                    env[instruction["out"]] = Datum(frozenset({instruction["id"]}))
                elif kind == "bool":
                    flag = instruction["value"]
                    env[instruction["out"]] = Datum(boolean=next(self.choices, False) if flag is None else flag)
                elif kind == "copy":
                    env[instruction["out"]] = env[instruction["value"]]
                elif kind == "alloc":
                    pointer = len(self.heap)
                    self.heap[pointer] = {name: env[reg] for name, reg in instruction["fields"].items()}
                    env[instruction["out"]] = Datum(reference=pointer)
                elif kind == "load":
                    pointer = env[instruction["object"]].reference
                    env[instruction["out"]] = self.heap[pointer][instruction["field"]]
                elif kind == "store":
                    pointer = env[instruction["object"]].reference
                    self.heap[pointer][instruction["field"]] = env[instruction["value"]]
                elif kind == "sink":
                    value = env[instruction["value"]]
                    if value.sources:
                        self.findings.setdefault(instruction["id"], set()).update(value.sources)
                elif kind == "jump":
                    block = instruction["target"]
                elif kind == "branch":
                    block = instruction["yes"] if env[instruction["condition"]].boolean else instruction["no"]
                elif kind == "invoke":
                    binding = self.document["bindings"][instruction["site"]]
                    target = self.document["functions"][binding["callee"]]
                    arguments = [env[binding["actuals"][param]] for param in target["params"]]
                    tag, value = self.call(binding["callee"], arguments)
                    if tag is None:
                        env[instruction["out"]], block = value, instruction["normal"]
                    else:
                        handler = instruction.get("catch", {}).get(tag, instruction.get("catch", {}).get("*"))
                        if handler is None:
                            return tag, value
                        env[instruction["error"]], block = value, handler
                elif kind == "return":
                    return None, env[instruction["value"]]
                elif kind == "raise":
                    return instruction["tag"], env[instruction["value"]]
                else:
                    raise ValueError(kind)

    def run(self):
        self.call(self.document["entry"], [])
        return self.findings
