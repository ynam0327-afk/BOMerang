# BOMerang CycloneDX 1.6 converter

## Input formats

- Integrated parser JSON: `{"files": [...], "dependencies": [...]}`
- Flat dependency JSON list, such as `spring-exclusions.json` (UTF-16 or UTF-8)
- Optional risk analysis JSON, such as `spring-risk.json` (UTF-8)

The converter does not query OSV/NVD or recalculate risk scores. It preserves the existing risk-analysis results and links each finding to its component by exact PURL.

## Convert the teammate's two JSON files

From the BOMerang project root:

```powershell
python cyclonedx_converter.py spring-exclusions.json --risk spring-risk.json -o spring-bom.cdx.json --name spring-exclusions
```

## Convert integrated parser output without risk data

```powershell
python integrated_parser.py <target-project-path> > integrated.json
python cyclonedx_converter.py integrated.json -o bom.cdx.json
```

Check the actual CLI arguments supported by `integrated_parser.py` in your checked-out branch before running the first command; the converter accepts its JSON output format.

## Run converter tests

```powershell
python -m unittest -v test_cyclonedx_converter.py
```

The output BOM uses CycloneDX 1.6 `components`, `dependencies`, and `vulnerabilities`. BOMerang-specific fields such as `priority_score`, `score_breakdown`, and `review_required` are retained as `bomerang:*` properties. `review_required=true` means manual review is needed; it does not establish exploitability.
