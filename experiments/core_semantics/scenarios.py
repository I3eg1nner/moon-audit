"""Hand-written IR witnesses. These are not MoonBit frontend coverage tests."""


def op(kind, **fields):
    return {"op": kind, **fields}


def function(params, blocks, entry="entry"):
    return {"params": params, "blocks": blocks, "entry": entry}


def observe(register="a", fields=("value", "safe"), prefix="main"):
    result = []
    for field in fields:
        result += [op("load", out=f"read_{register}_{field}", object=register, field=field),
                   op("sink", id=f"{prefix}/{register}.{field}", value=f"read_{register}_{field}")]
    return result


def alias_program(effect="read_after_write", alias=True):
    prefix = [op("source", id="helper/source", out="dirty"), op("clean", out="clean")]
    writes = {
        "read_after_write": [op("store", object="first", field="value", value="dirty"),
                             op("load", out="read", object="second", field="value"),
                             op("store", object="second", field="safe", value="read")],
        "clean_last": [op("store", object="first", field="value", value="dirty"),
                       op("store", object="second", field="value", value="clean")],
        "dirty_last": [op("store", object="first", field="value", value="clean"),
                       op("store", object="second", field="value", value="dirty")],
        "return_before_clear": [op("store", object="first", field="value", value="dirty"),
                                op("load", object="first", field="value", out="ret"),
                                op("store", object="first", field="value", value="clean")],
    }[effect]
    helper = prefix + writes + [op("return", value="ret" if effect == "return_before_clear" else "clean")]
    main = [op("clean", out="clean"),
            op("alloc", site="alloc/main/a", out="a", fields={"value": "clean", "safe": "clean"}),
            op("alloc", site="alloc/main/b", out="b", fields={"value": "clean", "safe": "clean"}),
            op("invoke", site="call/main/fill", normal="after", out="result")]
    after = observe("a") + observe("b") + [op("sink", id="main/result", value="result"), op("return", value="clean")]
    return {"entry": "demo/main", "functions": {
        "demo/main": function([], {"entry": main, "after": after}),
        "demo/fill": function(["first", "second"], {"entry": helper}),
    }, "bindings": {"call/main/fill": {"callee": "demo/fill", "actuals": {"first": "a", "second": "a" if alias else "b"}}}}


def exception_program(dirty_exit="normal", clear_error=False):
    document = alias_program()
    main = document["functions"]["demo/main"]
    invoke = main["blocks"]["entry"][-1]
    invoke.update(catch={"demo/Err": "catch"}, error="error")
    main["blocks"]["after"] = observe(prefix="normal") + [op("return", value="clean")]
    main["blocks"]["catch"] = observe(prefix="exception") + [op("return", value="clean")]
    if clear_error:
        main["blocks"]["entry"].insert(1, op("source", id="main/input", out="initial"))
        main["blocks"]["entry"][2]["fields"]["value"] = "initial"
    head = [op("source", id="helper/source", out="dirty"), op("clean", out="clean"),
            op("bool", out="flag", value=None), op("branch", condition="flag", yes="throw", no="normal")]
    normal = [op("store", object="first", field="value", value="dirty" if dirty_exit == "normal" else "clean"),
              op("return", value="clean")]
    throw = [op("store", object="first", field="value", value="dirty" if dirty_exit == "exception" else "clean"),
             op("raise", tag="demo/Err", value="clean")]
    document["functions"]["demo/fill"] = function(["first", "second"], {"entry": head, "normal": normal, "throw": throw})
    return document


def exception_payload_program():
    document = exception_program("exception")
    document["functions"]["demo/fill"]["blocks"]["throw"][-1]["value"] = "first"
    catcher = document["functions"]["demo/main"]["blocks"]["catch"]
    catcher[:0] = [op("load", object="error", field="value", out="payload_value"),
                  op("sink", id="exception/payload.value", value="payload_value")]
    return document


def recursive_program():
    document = alias_program()
    document["functions"]["demo/fill"] = function(["first", "second"], {
        "entry": [op("bool", out="again", value=None), op("branch", condition="again", yes="recurse", no="base")],
        "base": [op("source", id="helper/source", out="dirty"),
                 op("store", object="first", field="value", value="dirty"), op("return", value="dirty")],
        "recurse": [op("invoke", site="call/fill/self", out="recursive_result", normal="done")],
        "done": [op("return", value="recursive_result")],
    })
    document["bindings"]["call/fill/self"] = {"callee": "demo/fill", "actuals": {"first": "first", "second": "second"}}
    return document


def possible_alias_program():
    return {"entry": "demo/main", "functions": {
        "demo/main": function([], {
            "entry": [op("source", id="main/input", out="dirty"), op("clean", out="clean"),
                      op("alloc", site="alloc/a", out="a", fields={"value": "dirty"}),
                      op("alloc", site="alloc/b", out="b", fields={"value": "dirty"}),
                      op("bool", out="flag", value=None), op("branch", condition="flag", yes="left", no="right")],
            "left": [op("copy", out="target", value="a"), op("jump", target="call")],
            "right": [op("copy", out="target", value="b"), op("jump", target="call")],
            "call": [op("invoke", site="call/clear", out="result", normal="after")],
            "after": observe("a", ("value",)) + observe("b", ("value",)) + [op("return", value="clean")],
        }),
        "demo/clear": function(["target"], {"entry": [op("clean", out="clean"),
            op("store", object="target", field="value", value="clean"), op("return", value="clean")]}),
    }, "bindings": {"call/clear": {"callee": "demo/clear", "actuals": {"target": "target"}}}}


def factory_program():
    return {"entry": "demo/main", "functions": {
        "demo/main": function([], {
            "entry": [op("source", id="main/input", out="dirty"), op("clean", out="clean"),
                      op("invoke", site="call/first", out="a", normal="second")],
            "second": [op("invoke", site="call/second", out="b", normal="after")],
            "after": observe("a", ("value",)) + observe("b", ("value",)) + [op("return", value="clean")],
        }),
        "demo/make": function(["value"], {"entry": [op("alloc", site="alloc/factory", out="box", fields={"value": "value"}),
                                                   op("return", value="box")]}),
    }, "bindings": {
        "call/first": {"callee": "demo/make", "actuals": {"value": "dirty"}},
        "call/second": {"callee": "demo/make", "actuals": {"value": "clean"}},
    }}


def witnesses():
    cases = {}
    for effect in ("read_after_write", "clean_last", "dirty_last", "return_before_clear"):
        for alias in (True, False):
            cases[f"{effect}/{'alias' if alias else 'distinct'}"] = alias_program(effect, alias)
    cases.update({"exception/normal_dirty": exception_program(),
                  "exception/throw_dirty": exception_program("exception"),
                  "exception/clear": exception_program("neither", True),
                  "exception/payload_object": exception_payload_program(),
                  "recursive/fixed_point": recursive_program(),
                  "alias/possible": possible_alias_program(),
                  "factory/distinct_calls": factory_program()})
    return cases


def call_chain(size, objects=False):
    """Deterministic cost witness; distinct from real corpus performance."""
    prefix = [op("clean", out="value")]
    if objects:
        prefix += [op("alloc", site=f"alloc/{i}", out=f"object_{i}", fields={"value": "value"}) for i in range(size)]
    blocks = {"entry": prefix + [op("jump", target="call_0")]}
    bindings = {}
    for i in range(size):
        site = f"call/{i}"
        blocks[f"call_{i}"] = [op("invoke", site=site, out="result", normal=f"call_{i+1}")]
        bindings[site] = {"callee": "demo/step", "actuals": {"value": f"object_{i}" if objects else "value"}}
    blocks[f"call_{size}"] = [op("return", value="value")]
    body = [op("return", value="value")]
    if objects:
        body = [op("clean", out="clean"), op("store", object="value", field="value", value="clean"), op("return", value="clean")]
    return {"entry": "demo/main", "functions": {"demo/main": function([], blocks),
            "demo/step": function(["value"], {"entry": body})}, "bindings": bindings}
