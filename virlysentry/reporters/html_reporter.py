from jinja2 import Template

from virlysentry.core.models import ScanResult

_TEMPLATE = Template("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>VirlySentry Report - {{ target }}</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 32px; background: #0b0f14; color: #d8e1e8; }
  h1 { color: #ffffff; }
  .meta { color: #8fa3b3; margin-bottom: 24px; }
  .summary { display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; }
  .badge { padding: 8px 14px; border-radius: 8px; font-weight: 600; }
  .CRITICAL { background: #4a0e5c; color: #f0c3ff; }
  .HIGH { background: #5c0e0e; color: #ffc3c3; }
  .MEDIUM { background: #5c4a0e; color: #fff0c3; }
  .LOW { background: #0e4a5c; color: #c3f0ff; }
  .INFO { background: #2a2a2a; color: #cccccc; }
  .finding { border: 1px solid #1c2733; border-radius: 10px; padding: 16px; margin-bottom: 14px; background: #10161d; }
  .finding h3 { margin: 0 0 8px 0; }
  .field { margin: 6px 0; }
  .label { color: #8fa3b3; font-weight: 600; margin-right: 6px; }
  pre { background: #0d1420; padding: 10px; border-radius: 6px; overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; }
  td, th { border-bottom: 1px solid #1c2733; padding: 8px; text-align: left; font-size: 14px; }
</style>
</head>
<body>
  <h1>VirlySentry Security Scan Report</h1>
  <div class="meta">
    Target: {{ target }} &nbsp;|&nbsp; Files scanned: {{ result.files_scanned }}
    &nbsp;|&nbsp; Duration: {{ "%.2f"|format(result.duration_seconds) }}s
  </div>

  <div class="summary">
    {% for sev, count in severity_counts.items() %}
      {% if count > 0 %}
      <div class="badge {{ sev }}">{{ sev }}: {{ count }}</div>
      {% endif %}
    {% endfor %}
  </div>

  {% for f in result.findings %}
  <div class="finding">
    <h3><span class="badge {{ f.severity.label() }}">{{ f.severity.label() }}</span>&nbsp; [{{ f.rule_id }}] {{ f.title }}</h3>
    <div class="field"><span class="label">Location:</span> {{ f.file_path }}:{{ f.line_number }}:{{ f.column }}</div>
    {% if f.owasp %}<div class="field"><span class="label">OWASP:</span> {{ f.owasp }} {% if f.cwe %}| {{ f.cwe }}{% endif %}</div>{% endif %}
    <div class="field"><span class="label">Vulnerable code:</span></div>
    <pre>{{ f.code_snippet }}</pre>
    <div class="field"><span class="label">Scenario:</span> {{ f.scenario }}</div>
    <div class="field"><span class="label">Recommendation:</span> {{ f.recommendation }}</div>
    <div class="field"><span class="label">Suggested fix:</span></div>
    <pre>{{ f.fixed_example }}</pre>
  </div>
  {% else %}
  <p>No vulnerability findings above the configured severity threshold.</p>
  {% endfor %}

  {% if result.dead_code %}
  <h2>Dead Code / Unused Definitions</h2>
  <table>
    <tr><th>Kind</th><th>Name</th><th>Location</th><th>Reason</th></tr>
    {% for d in result.dead_code %}
    <tr><td>{{ d.kind }}</td><td>{{ d.name }}</td><td>{{ d.file_path }}:{{ d.line_number }}</td><td>{{ d.reason }}</td></tr>
    {% endfor %}
  </table>
  {% endif %}
</body>
</html>
""")


def render_html_report(result: ScanResult, target: str) -> str:
    return _TEMPLATE.render(result=result, target=target, severity_counts=result.severity_counts())
