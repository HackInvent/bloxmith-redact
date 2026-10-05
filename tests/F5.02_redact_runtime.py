"""FB4: real disposable wallet, deterministic pseudonyms and both runtimes/package origins."""

from pathlib import Path
import json
import sys

ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT),str(ROOT/"tests")]
from blocs.redact.block import RedactBlock
from block_test_packages import install_test_package,surface_payload
from ui_smoke_common import create_project_api,create_run_api,data_edge,display_node,graph_payload,http_json,isolated_server,text_node,wait_for_run_terminal


def main():
    key="isolated-redaction-fixture-key-32"
    block=RedactBlock()
    for mode in ("centralized","zeromq_active"):
        for origin in (None,"managed","linked"):
            with isolated_server() as server:
                node=block.build_node_payload(node_id="redaction",position={"x":360,"y":140})
                node["config"]={**block.default_config(),"input_format":"json","action":"pseudonymize",
                                "secret_ref":"secret://workspace/fixture_redact"}
                if origin:
                    model=install_test_package(server,"redact",origin=origin)
                    node["block_version"]=model["version"]
                    for surface in ("modal","inspector_panel","node_card"):
                        html=surface_payload(server,model,node,surface=surface)["html"]
                        assert "{{" not in html and key not in html
                http_json(server.base_url,"/api/application/secrets/init",method="POST",
                          payload={"password":"disposable-redaction-fixture"})
                http_json(server.base_url,"/api/application/secrets",method="POST",
                          payload={"name":"fixture_redact","value":key})
                graph=graph_payload("Minimize data",[text_node("source","Private input",
                    '{"token":"private-value","contact":"reviewer@example.test","count":3}',80,140),
                    node,display_node("display","Filtered output",700,140)],[data_edge("input","source",1,"redaction",1),
                    data_edge("result","redaction",1,"display",1)])
                project=create_project_api(server,document=graph)["project"]
                results=[]
                for _ in range(2):
                    run=create_run_api(server,graph,project_id=project["graph_id"],runtime_mode=mode)
                    result=wait_for_run_terminal(server,run["run_id"],timeout_sec=30)
                    assert result["status"]=="success",(mode,origin,result.get("logs"))
                    output=json.loads(result["output_values"]["redaction:1"]["value"])
                    assert output["count"]==3 and output["token"].startswith("[redacted:")
                    assert "private-value" not in json.dumps(output) and "reviewer@example" not in json.dumps(output)
                    assert key not in json.dumps(result)
                    report=json.loads(result["output_values"]["redaction:2"]["value"])
                    assert report["total"]==2 and report["coverage"]=="configured_rules_only"
                    results.append(output)
                assert results[0]==results[1]
                http_json(server.base_url,"/api/application/secrets/lock",method="POST",payload={})
                run=create_run_api(server,graph,project_id=project["graph_id"],runtime_mode=mode)
                denied=wait_for_run_terminal(server,run["run_id"],timeout_sec=30)
                assert denied["status"]=="failed" and "redaction:1" not in denied["output_values"]
                assert key not in json.dumps(denied)
            print("[ok] Redact wallet "+mode+" "+str(origin),flush=True)


if __name__=="__main__":
    main()
