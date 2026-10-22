#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/cloudtrail-operations.json from botocore's models.

A CloudTrail record names the operation the caller invoked (`eventName`), the service endpoint it
was sent to (`eventSource`), and mirrors the operation's input in `requestParameters` and its output
in `responseElements`, keyed by the model's member names with the first letter lowercased (the
Query and EC2 protocols use each member's `locationName`), with every member the model marks
`sensitive` replaced by `HIDDEN_DUE_TO_SECURITY_REASONS`. `OperationResolver` and
`CloudTrailRecordBuilder` read all of that from this file.

Per model:
  signingName   the credential scope its requests are signed for
  eventSource   `<endpointPrefix>.amazonaws.com`, the form CloudTrail records in every partition
  protocol      the model's wire protocol
  apiVersion    the model's API version
  targetPrefix  the `X-Amz-Target` prefix (JSON protocols only)
  operations    per operation: `input`/`output` shape names, and for REST protocols the HTTP
                `method`, the request URI template `uri`, the query literals the URI requires,
                and the `headers` and `queryParameters` the input requires
  shapes        the structures, lists and maps reachable from an operation, without scalars:
                  structure  {"members": {Member: Shape or ""}, "locationNames": {...},
                              "sensitive": [...], "blobs": [...], "timestamps": [...]}
                  list       {"list": Shape or "", "locationName": "...", "sensitive": true}
                  map        {"map": true}

The models are botocore's `<model>/<apiVersion>/service-2.json` (Apache-2.0,
https://github.com/boto/botocore), the latest API version of each. A model is included when a
credential scope `ResolvedServiceCatalog` registers is its signing name.

Run from anywhere in the repo:
    python3 tools/aws/regen_cloudtrail_operations.py            # rewrite the vendored file in place
    python3 tools/aws/regen_cloudtrail_operations.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from regen_partitions import load_model, resolve_botocore_data, service_model, strip_source

REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT = REPO_ROOT / "src/main/resources/aws/cloudtrail-operations.json"
CATALOG = REPO_ROOT / "src/main/java/io/github/hectorvent/floci/core/common/ResolvedServiceCatalog.java"

CREDENTIAL_SCOPES_RE = re.compile(r"protocols\([^)]*\),\s*Set\.of\([^)]*\),\s*Set\.of\(([^)]*)\)")
REST_PROTOCOLS = ("rest-json", "rest-xml")
LOCATION_NAME_PROTOCOLS = ("query", "ec2")


def catalog_scopes(java_source: str) -> set[str]:
    """Every credential scope a `descriptor(...)` call in `ResolvedServiceCatalog` registers."""
    scopes = set()
    code = re.sub(r"//[^\n]*", "", java_source)
    for group in CREDENTIAL_SCOPES_RE.findall(code):
        scopes.update(re.findall(r'"([^"]+)"', group))
    if not scopes:
        raise SystemExit(f"error: no credential scopes found in {CATALOG}")
    return scopes


def signing_name(model: dict) -> str:
    metadata = model["metadata"]
    return metadata.get("signingName") or metadata["endpointPrefix"]


def query_literals(request_uri: str) -> dict[str, str]:
    if "?" not in request_uri:
        return {}
    literals = {}
    for part in request_uri.split("?", 1)[1].split("&"):
        key, _, value = part.partition("=")
        literals[key] = value
    return literals


def required_members(model: dict, operation: dict, location: str) -> list[str]:
    """The headers or query parameters a REST operation's input requires, which tell CopyObject from
    PutObject, or UploadPart from PutObject, on one route."""
    if "input" not in operation:
        return []
    shape = model["shapes"][operation["input"]["shape"]]
    members = shape.get("members", {})
    return sorted(members[name]["locationName"] for name in shape.get("required", [])
                  if members[name].get("location") == location)


def is_sensitive(shapes: dict, ref: dict) -> bool:
    return bool(ref.get("sensitive") or shapes[ref["shape"]].get("sensitive"))


def compact_shapes(model: dict, roots: list[str]) -> dict:
    """The structures, lists and maps reachable from `roots`, reduced to what a record needs."""
    shapes = model["shapes"]
    use_location = model["metadata"]["protocol"] in LOCATION_NAME_PROTOCOLS
    out: dict[str, dict] = {}
    pending = [root for root in roots if root]

    def target(name: str) -> str:
        if shapes[name]["type"] in ("structure", "list", "map"):
            pending.append(name)
            return name
        return ""

    while pending:
        name = pending.pop()
        if name in out:
            continue
        shape = shapes[name]
        kind = shape["type"]
        if kind == "structure":
            entry: dict = {"members": {}}
            out[name] = entry
            lists: dict[str, list | dict] = {"locationNames": {}, "sensitive": [], "blobs": [], "timestamps": []}
            for member, ref in shape.get("members", {}).items():
                entry["members"][member] = target(ref["shape"])
                if use_location and ref.get("locationName", member) != member:
                    lists["locationNames"][member] = ref["locationName"]
                if is_sensitive(shapes, ref):
                    lists["sensitive"].append(member)
                if shapes[ref["shape"]]["type"] in ("blob", "timestamp"):
                    lists[shapes[ref["shape"]]["type"] + "s"].append(member)
            entry.update({key: value for key, value in lists.items() if value})
        elif kind == "list":
            ref = shape["member"]
            entry = {"list": ""}
            out[name] = entry
            entry["list"] = target(ref["shape"])
            if use_location and "locationName" in ref:
                entry["locationName"] = ref["locationName"]
            if is_sensitive(shapes, ref):
                entry["sensitive"] = True
        elif kind == "map":
            out[name] = {"map": True}
    return dict(sorted(out.items()))


def build_model(model: dict) -> dict:
    metadata = model["metadata"]
    protocol = metadata["protocol"]
    operations = {}
    roots = []
    for name in sorted(model["operations"]):
        operation = model["operations"][name]
        entry: dict = {}
        if protocol in REST_PROTOCOLS:
            http = operation["http"]
            entry["method"] = http["method"]
            entry["uri"] = http["requestUri"].split("?", 1)[0]
            literals = query_literals(http["requestUri"])
            if literals:
                entry["query"] = literals
            for key, location in (("headers", "header"), ("queryParameters", "querystring")):
                names = required_members(model, operation, location)
                if names:
                    entry[key] = names
        for side in ("input", "output"):
            if side in operation:
                entry[side] = operation[side]["shape"]
                roots.append(operation[side]["shape"])
        operations[name] = entry
    doc: dict = {
        "signingName": signing_name(model),
        "eventSource": f"{metadata['endpointPrefix']}.amazonaws.com",
        "protocol": protocol,
        "apiVersion": metadata["apiVersion"],
    }
    if "targetPrefix" in metadata:
        doc["targetPrefix"] = metadata["targetPrefix"]
    doc["operations"] = operations
    doc["shapes"] = compact_shapes(model, roots)
    return doc


def build(models: dict[str, dict], provenance: str) -> dict:
    return {
        "_source": {"generator": "tools/aws/regen_cloudtrail_operations.py", "botocore": provenance},
        "models": {name: build_model(models[name]) for name in sorted(models)},
    }


def load_models(data: Path, scopes: set[str]) -> dict[str, dict]:
    models = {}
    for directory in sorted(path for path in data.iterdir() if path.is_dir()):
        versions = sorted(path for path in directory.iterdir() if path.is_dir())
        path = service_model(versions[-1]) if versions else None
        if path is None:
            continue
        model = load_model(path)
        if signing_name(model) in scopes:
            models[directory.name] = model
    return models


def render(doc: dict) -> str:
    """The document with one model to a line, so a regeneration diffs by service."""
    lines = ["{", f'"_source":{json.dumps(doc["_source"], separators=(",", ":"))},', '"models":{']
    models = list(doc["models"].items())
    for index, (name, model) in enumerate(models):
        comma = "," if index < len(models) - 1 else ""
        lines.append(f"{json.dumps(name)}:{json.dumps(model, separators=(',', ':'))}{comma}")
    lines += ["}", "}"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="exit 1 when the vendored file differs from a fresh generation")
    parser.add_argument("--botocore-data", type=Path, help="botocore data directory")
    parser.add_argument("--catalog", type=Path, default=CATALOG, help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, default=OUTPUT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    data, provenance = resolve_botocore_data(args.botocore_data)
    scopes = catalog_scopes(args.catalog.read_text(encoding="utf-8"))
    fresh = render(build(load_models(data, scopes), provenance))

    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.exists() else ""
        if strip_source(current) != strip_source(fresh):
            print(f"{args.output} is stale (generated from {provenance}).", file=sys.stderr)
            return 1
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(fresh, encoding="utf-8")
    shown = args.output.relative_to(REPO_ROOT) if args.output.is_relative_to(REPO_ROOT) else args.output
    print(f"wrote {shown} from {provenance}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
