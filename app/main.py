from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional
import json
import re
from pathlib import Path

app = FastAPI(title="Dynamic SAP Table Replacement Scanner")

# ---------------------------------------------------
# Load dynamic old→new table mapping
# ---------------------------------------------------
MAPPING_PATH = Path(__file__).parent / "tables.json"

with open(MAPPING_PATH, "r", encoding="utf-8") as f:
    TABLE_MAP = json.load(f)

OLD_TABLES = list(TABLE_MAP.keys())

# ---------------------------------------------------
# Build dynamic regex from table list
# ---------------------------------------------------
def build_regex():
    tbl = "|".join(sorted(OLD_TABLES, key=len, reverse=True))

    return {
        "DML": re.compile(
            rf"(?P<full>(?P<stmt>\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bMODIFY\b)[\s\S]*?\b(FROM|INTO|UPDATE|DELETE\s+FROM)\b\s+(?P<obj>{tbl})\b)",
            re.IGNORECASE,
        ),
        "CLEAR": re.compile(
            rf"(?P<full>(?P<stmt>CLEAR)\s+(?P<obj>{tbl})\b[\w\-]*)",
            re.IGNORECASE,
        ),
        "ASSIGN": re.compile(
            rf"(?P<full>(?P<obj>{tbl})[\w\-]*\s*=\s*[\w\-\>]+|[\w\-\>]+\s*=\s*(?P<obj2>{tbl})[\w\-]*)",
            re.IGNORECASE,
        ),
        "GENERIC": re.compile(
            rf"(?P<full>\b(?P<obj>{tbl})\b)",
            re.IGNORECASE,
        )
    }

REGEX = build_regex()


class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = None
    class_implementation: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    code: Optional[str] = ""


# ---------------------------------------------------
# Extract small preview snippet
# ---------------------------------------------------
def snippet_at(text: str, start: int, end: int) -> str:
    s = max(0, start - 60)
    e = min(len(text), end + 60)
    return text[s:e].replace("\n", "\\n")


# ---------------------------------------------------
# Main finder
# ---------------------------------------------------
def find_table_usage(txt: str):
    matches = []
    seen = set()   # prevent duplicates

    for name, pattern in REGEX.items():
        for m in pattern.finditer(txt or ""):
            obj = m.groupdict().get("obj") or m.groupdict().get("obj2")
            start, end = m.span("full")

            # Unique key based on TABLE + LINE NUMBER
            line_no = txt[:start].count("\n") + 1
            key = (obj, line_no)

            if key in seen:
                continue
            seen.add(key)

            replacement = TABLE_MAP.get(obj.upper())

            matches.append({
                "full": m.group("full"),
                "stmt": m.groupdict().get("stmt") or "=",
                "object": obj,
                "replacement_table": replacement,
                "ambiguous": replacement is None,
                "suggested_statement": f"Replace {obj} with {replacement}" if replacement else None,
                "span": (start, end)
            })

    matches.sort(key=lambda x: x["span"][0])
    return matches

# ---------------------------------------------------
# API: /remediate-tables
# ---------------------------------------------------
@app.post("/remediate-tables")
def remediate_tables(units: List[Unit]):
    results = []

    for u in units:
        src = u.code or ""
        metadata = []

        for m in find_table_usage(src):
            start, end = m["span"]
            metadata.append({
                "table": m["object"],
                "target_type": "TABLE",
                "target_name": m["object"],
                "start_char_in_unit": start,
                "end_char_in_unit": end,
                "used_fields": [],
                "ambiguous": m["ambiguous"],
                "suggested_statement": m["suggested_statement"],
                "new_table": m["replacement_table"],
                "snippet": snippet_at(src, start, end),
            })

        obj = json.loads(u.model_dump_json())
        obj["table_replacements"] = metadata
        results.append(obj)

    return results
