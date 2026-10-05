"""Deterministic configured minimization; not universal anonymization or PDF redaction."""

from collections.abc import Mapping
import hashlib
import hmac
import json
import math
import re

DEFAULTS={"input_format":"text","action":"mask","fields":["password","token","authorization","api_key","secret"],
          "emails":True,"literals":[],"mask":"[REDACTED]","secret_ref":"","max_bytes":1048576,"max_matches":10000}
EMAIL=re.compile(r"(?<![\w.%+\-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){1,4}(?![\w%+\-]|\.[\w-])")


class RedactError(ValueError):
    """Only fixed diagnostics are exposed, never original values."""


def configuration(raw):
    """Policy is configuration only; content cannot override it."""
    if not isinstance(raw,Mapping) or set(raw)-set(DEFAULTS)-{"execution","runtime_path","runtime_path_label"}:
        raise RedactError("Unknown setting.")
    cfg={**DEFAULTS,**{k:v for k,v in raw.items() if k in DEFAULTS}}
    if cfg["input_format"] not in ("text","json") or cfg["action"] not in ("mask","remove","pseudonymize"):
        raise RedactError("Choose an explicit format and replacement action.")
    for key,count,length in (("fields",100,128),("literals",32,128)):
        values=cfg[key]
        if not isinstance(values,(list,tuple)) or len(values)>count or any(not isinstance(v,str) or not 1<=len(v)<=length or "\x00" in v for v in values):
            raise RedactError("Invalid field-name or literal list.")
        if len(set(values))!=len(values):
            raise RedactError("Configured lists must contain distinct values.")
        cfg[key]=list(values)
    if type(cfg["emails"]) is not bool:
        raise RedactError("emails must be a boolean.")
    if not isinstance(cfg["mask"],str) or not 1<=len(cfg["mask"])<=64 or "\x00" in cfg["mask"]:
        raise RedactError("Mask must be 1–64 literal characters.")
    if not isinstance(cfg["secret_ref"],str) or len(cfg["secret_ref"])>512 or "\x00" in cfg["secret_ref"]:
        raise RedactError("Invalid wallet reference.")
    for key,low,high in (("max_bytes",1024,2097152),("max_matches",1,50000)):
        if type(cfg[key]) is not int or not low<=cfg[key]<=high:
            raise RedactError("A numeric limit is outside its allowed range.")
    return cfg


def document(raw,cfg):
    """Reject duplicate JSON keys, non-finite numbers and excessive shape before any replacement."""
    if not isinstance(raw,str) or len(raw.encode("utf-8"))>cfg["max_bytes"]:
        raise RedactError("Content must be bounded UTF-8 text.")
    if cfg["input_format"]=="text":
        return raw
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:
                raise RedactError("Duplicate JSON properties are not allowed.")
            result[key]=value
        return result
    try:
        value=json.loads(raw,object_pairs_hook=pairs,
            parse_constant=lambda _:(_ for _ in ()).throw(RedactError("Finite JSON is required.")))
    except (json.JSONDecodeError,RecursionError):
        raise RedactError("Invalid or excessively nested JSON.") from None
    stack=[(value,0)]
    nodes=0
    while stack:
        item,depth=stack.pop()
        nodes+=1
        if depth>24 or nodes>50000:
            raise RedactError("JSON exceeds its depth or node limit.")
        if isinstance(item,float) and not math.isfinite(item):
            raise RedactError("Finite JSON is required.")
        if isinstance(item,dict):
            stack.extend((child,depth+1) for child in item.values())
        elif isinstance(item,list):
            stack.extend((child,depth+1) for child in item)
    return value


def process(raw,options,resolve_secret=None,cancel=lambda:False):
    """No original content appears in the report; output is all-or-nothing."""
    cfg=configuration(options)
    value=document(raw,cfg)
    key=None
    if cfg["action"]=="pseudonymize":
        if not cfg["secret_ref"].strip() or not callable(resolve_secret):
            raise RedactError("Pseudonymization requires a wallet key reference.")
        try:
            secret=resolve_secret(cfg["secret_ref"])
        except Exception:
            raise RedactError("Pseudonym key could not be resolved.") from None
        if not isinstance(secret,str) or not 16<=len(secret.encode("utf-8"))<=4096:
            raise RedactError("Pseudonym key must contain 16–4096 UTF-8 bytes.")
        key=secret.encode("utf-8")
    counts={"fields":0,"emails":0,"literals":0}
    names={name.casefold() for name in cfg["fields"]}
    examined=0

    def check():
        if cancel():
            raise RedactError("Redaction cancelled.")

    def count(category):
        counts[category]+=1
        if sum(counts.values())>cfg["max_matches"]:
            raise RedactError("Replacement limit exceeded.")

    def marker(item):
        if cfg["action"]=="remove":
            return ""
        if key is None:
            return cfg["mask"]
        canonical=json.dumps(item,ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False).encode("utf-8")
        return "[redacted:"+hmac.new(key,b"bloxsmith-redact-v1\x00"+canonical,hashlib.sha256).hexdigest()[:32]+"]"

    def replace(text):
        nonlocal examined
        check()
        candidates=[]
        def candidate(start,end,category):
            nonlocal examined
            examined+=1
            if examined>cfg["max_matches"]*4:
                raise RedactError("Pattern matching limit exceeded.")
            candidates.append((start,-(end-start),end,category))
        if cfg["emails"]:
            for match in EMAIL.finditer(text):
                candidate(match.start(),match.end(),"emails")
                check()
        for literal in cfg["literals"]:
            check()
            offset=0
            while True:
                found=text.find(literal,offset)
                if found<0:
                    break
                candidate(found,found+len(literal),"literals")
                offset=found+len(literal)
        cursor=0
        parts=[]
        for start,_,end,category in sorted(candidates):
            if start<cursor:
                continue
            check()
            parts.extend((text[cursor:start],marker(text[start:end])))
            count(category)
            cursor=end
        parts.append(text[cursor:])
        return "".join(parts)

    def visit(item):
        check()
        if isinstance(item,dict):
            result={}
            for name,child in item.items():
                if name.casefold() in names:
                    count("fields")
                    if cfg["action"]!="remove":
                        result[name]=marker(child)
                else:
                    result[name]=visit(child)
            return result
        if isinstance(item,list):
            return [visit(child) for child in item]
        return replace(item) if isinstance(item,str) else item

    output=visit(value) if cfg["input_format"]=="json" else replace(value)
    serialized=json.dumps(output,ensure_ascii=False,allow_nan=False) if cfg["input_format"]=="json" else output
    # Marker expansion is bounded too; do not silently truncate a transformed document.
    if len(serialized.encode("utf-8"))>cfg["max_bytes"]*4:
        raise RedactError("Transformed output exceeds its expansion limit.")
    if key is not None:
        def contains(item):
            if isinstance(item,str):
                return secret in item
            if isinstance(item,dict):
                return any(secret in name or contains(child) for name,child in item.items())
            if isinstance(item,list):
                return any(contains(child) for child in item)
            return False
        if contains(output):
            raise RedactError("Output would expose the resolved pseudonym key.")
    check()
    return {"redacted":serialized,"report":{"format":cfg["input_format"],"action":cfg["action"],
        "replacements":counts,"total":sum(counts.values()),"changed":output!=value,
        "coverage":"configured_rules_only","reversible_mapping_stored":False}}
