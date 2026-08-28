"""Write scan results out to CSV or JSON."""
import csv
import json

from core.services.fuzzer import HEADERS


def to_csv(results, path: str):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(HEADERS)
        writer.writerows(results)


def to_json(results, path: str):
    keys = [h.lower().replace(" ", "_").replace("#", "index") for h in HEADERS]
    payload = [dict(zip(keys, row)) for row in results]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def export(results, path: str):
    if path.lower().endswith(".json"):
        to_json(results, path)
    else:
        to_csv(results, path)
