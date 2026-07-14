import json

from virlysentry.core.models import ScanResult


def render_json_report(result: ScanResult, target: str) -> str:
    payload = result.to_dict()
    payload["target"] = target
    payload["product"] = "VirlySentry"
    return json.dumps(payload, indent=2)
