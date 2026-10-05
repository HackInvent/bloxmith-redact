"""FB1/FB2/FB3: explicit minimization, deterministic keyed tokens and non-leaking failures."""

import json
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT),str(ROOT/"tests")]
from blocs.redact import logic
from blocs.redact.block import RedactBlock
from bloxsmith_app.block_api import BlockRuntimeContext


def rejected(call):
    try:
        call()
    except (ValueError,TypeError):
        return
    raise AssertionError("Unsafe input was accepted")


def main():
    result=logic.process("Contact user@example.test; literal PRIVATE.",{"literals":["PRIVATE"]})
    assert result["redacted"]=="Contact [REDACTED]; literal [REDACTED].",result
    assert result["report"]["replacements"]=={"fields":0,"emails":1,"literals":1}
    assert "user@example" not in repr(result["report"]) and "PRIVATE" not in repr(result["report"])
    assert logic.process("Write user@example.test. Next sentence.",{})["redacted"] == "Write [REDACTED]. Next sentence."
    # Unsupported internationalized addresses are not partially matched as ASCII suffixes.
    assert logic.process("éx@example.test",{})["report"]["total"] == 0
    source={"password":{"nested":"hidden"},"items":[{"TOKEN":123,"visible":"a@example.test"}],"number":7,"ok":True}
    masked=logic.process(json.dumps(source),{"input_format":"json"})
    output=json.loads(masked["redacted"])
    assert output=={"password":"[REDACTED]","items":[{"TOKEN":"[REDACTED]","visible":"[REDACTED]"}],"number":7,"ok":True}
    removed=logic.process(json.dumps(source),{"input_format":"json","action":"remove"})
    assert json.loads(removed["redacted"])=={"items":[{"visible":""}],"number":7,"ok":True}
    assert source["items"][0]["TOKEN"]==123
    # Longest overlapping literal wins; inserted markers are not processed again.
    overlapping=logic.process("abc abc",{"emails":False,"literals":["ab","abc"],"mask":"abc"})
    assert overlapping["redacted"]=="abc abc" and overlapping["report"]["total"]==2
    assert overlapping["report"]["changed"] is False
    key="fixture-hmac-key-only-32-bytes-long"
    options={"input_format":"json","action":"pseudonymize","secret_ref":"fixture","fields":["a","b"],"emails":False}
    first=logic.process('{"a":"same","b":"same","c":"unchanged"}',options,lambda _:key)
    repeated=logic.process('{"a":"same","b":"same","c":"unchanged"}',options,lambda _:key)
    other=logic.process('{"a":"same","b":"same","c":"unchanged"}',options,lambda _:"another-fixture-key-only-32-bytes")
    decoded=json.loads(first["redacted"])
    assert decoded["a"]==decoded["b"] and decoded["a"].startswith("[redacted:")
    assert first["redacted"]==repeated["redacted"] and first["redacted"]!=other["redacted"]
    assert "same" not in first["redacted"] and key not in repr(first)
    assert not first["report"]["reversible_mapping_stored"]
    for config in ({"unknown":1},{"fields":"password"},{"literals":[""]},{"emails":"yes"},{"max_bytes":True},{"mask":""}):
        rejected(lambda config=config:logic.process("fixture",config))
    for raw in ('{"a":1,"a":2}','{"x":NaN}','{"x":1e400}','['*30+'0'+']'*30):
        rejected(lambda raw=raw:logic.process(raw,{"input_format":"json"}))
    rejected(lambda:logic.process("x"*1025,{"max_bytes":1024}))
    rejected(lambda:logic.process("aa",{"literals":["a"],"max_matches":1}))
    rejected(lambda:logic.process("fixture",{"action":"pseudonymize","secret_ref":"missing"}))
    rejected(lambda:logic.process("fixture",{"action":"pseudonymize","secret_ref":"short"},lambda _:"short"))
    rejected(lambda:logic.process(key,{"action":"pseudonymize","secret_ref":"fixture","emails":False},lambda _:key))
    rejected(lambda:logic.process("fixture",{},cancel=lambda:True))
    input_ports=(SimpleNamespace(id=8,name="content"),)
    output_ports=(SimpleNamespace(id=7,name="redacted"),SimpleNamespace(id=12,name="report"))
    context=BlockRuntimeContext(input_ports=input_ports,output_ports=output_ports,
                               inputs={"content":"u@example.test"},config={})
    reply=RedactBlock().execute_runtime(context)
    assert reply.status=="success" and reply.outputs[0].port_id==7
    assert reply.outputs[0].value=="[REDACTED]" and "u@example.test" not in repr(reply)
    context.config={"action":"pseudonymize","secret_ref":"missing"}
    failed=RedactBlock().execute_runtime(context)
    assert failed.status=="failed" and not failed.outputs and "u@example.test" not in repr(failed)
    print("[ok] Redact configured rules, limits and key handling")


if __name__=="__main__":
    main()
