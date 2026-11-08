"""Offline CycloneDX 1.6 validation against preserved official Draft-07 schemas."""
import argparse
from collections import Counter
import hashlib
import importlib.metadata
import json
from pathlib import Path

from jsonschema import Draft7Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent
SCHEMAS = ROOT / "security-fixtures/step5/schema"


def validator(schema_dir=SCHEMAS):
    schema_dir = Path(schema_dir)
    manifest = json.loads((schema_dir / "manifest.json").read_text(encoding="utf-8"))
    registry = Registry()
    documents = {}
    for entry in manifest["schemas"]:
        raw = (schema_dir / entry["file"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise ValueError("Official schema snapshot hash mismatch: " + entry["file"])
        document = json.loads(raw)
        Draft7Validator.check_schema(document)
        documents[entry["file"]] = document
        resource = Resource.from_contents(document)
        for uri in {entry["url"], entry["schema_id"], entry["schema_id"].replace("http:", "https:", 1)}:
            registry = registry.with_resource(uri, resource)
    return Draft7Validator(documents["bom-1.6.schema.json"], registry=registry,
                           format_checker=Draft7Validator.FORMAT_CHECKER)


def integrity_errors(bom):
    errors = []
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.6":
        errors.append("Expected CycloneDX 1.6")
    all_refs = []
    def visit(value):
        if isinstance(value, dict):
            if "bom-ref" in value:
                all_refs.append(value["bom-ref"])
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(bom)
    for ref, count in Counter(all_refs).items():
        if count > 1:
            errors.append("Duplicate bom-ref: " + str(ref))
    components = {c["bom-ref"] for c in bom.get("components", []) if c.get("bom-ref")}
    graph_refs = components | {s["bom-ref"] for s in bom.get("services", []) if s.get("bom-ref")}
    root_ref = bom.get("metadata", {}).get("component", {}).get("bom-ref")
    if root_ref:
        graph_refs.add(root_ref)
    for row in bom.get("dependencies", []):
        for ref in [row.get("ref"), *row.get("dependsOn", [])]:
            if ref not in graph_refs:
                errors.append("Dangling dependency reference: " + str(ref))
    ids = [v["id"] for v in bom.get("vulnerabilities", []) if v.get("id")]
    for value, count in Counter(ids).items():
        if count > 1:
            errors.append("Duplicate vulnerability ID: " + value)
    for vulnerability in bom.get("vulnerabilities", []):
        for affected in vulnerability.get("affects", []):
            if affected.get("ref") not in graph_refs:
                errors.append("Dangling vulnerability affects: " + str(affected.get("ref")))
    return errors


def validate_document(bom, schema_dir=SCHEMAS):
    schema_errors = [{"path": list(error.absolute_path), "message": error.message}
                     for error in validator(schema_dir).iter_errors(bom)]
    semantic_errors = integrity_errors(bom) if not schema_errors else []
    return {
        "official_schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "spec_version": "1.6", "schema_draft": "draft-07",
        "validator": {"jsonschema": importlib.metadata.version("jsonschema"),
                      "referencing": importlib.metadata.version("referencing"),
                      "format_checker": True, "network_resolution": "disabled; local registry only"},
        "schema_valid": not schema_errors, "schema_errors": schema_errors,
        "local_integrity_checked": not schema_errors,
        "local_integrity_valid": not semantic_errors if not schema_errors else None,
        "local_integrity_errors": semantic_errors,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--schema-dir", type=Path, default=SCHEMAS)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    bom = json.loads(args.input.read_text(encoding="utf-8-sig"))
    result = validate_document(bom, args.schema_dir)
    result["input"] = str(args.input.resolve())
    result["input_sha256"] = hashlib.sha256(args.input.read_bytes()).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"schema_valid": result["schema_valid"],
                      "local_integrity_valid": result["local_integrity_valid"]}))
    raise SystemExit(0 if result["schema_valid"] and result["local_integrity_valid"] else 1)


if __name__ == "__main__":
    main()
