"""Standalone (single-file, no external assets) HTML report."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from apkguard.model import Finding, Severity
from apkguard.rules import RULES_BY_ID
from apkguard.scanner import ScanResult

_CSS = """
:root{--bg:#f7f8fa;--card:#fff;--text:#1d2330;--muted:#5f6b7a;--border:#dfe3ea;
--critical:#b3132b;--high:#d9480f;--medium:#b7791f;--low:#1c7ed6;--info:#6b7280;--ok:#2b8a3e}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b2029;--text:#e6e9ef;
--muted:#9aa4b2;--border:#2c3340;--critical:#ff6b81;--high:#ff922b;--medium:#fcc419;
--low:#4dabf7;--info:#adb5bd;--ok:#69db7c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px}
.muted{color:var(--muted)}code{font:13px/1.4 ui-monospace,SFMono-Regular,Consolas,monospace;
word-break:break-all}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px;margin:16px 0}
.meta div{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:8px 12px}
.meta b{display:block;font-size:12px;color:var(--muted);font-weight:500}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px}
.card{background:var(--card);border:1px solid var(--border);border-left:4px solid var(--c);
border-radius:8px;padding:10px 14px;cursor:pointer;user-select:none}
.card.off{opacity:.45}.card .n{font-size:26px;font-weight:700;color:var(--c)}
.card .l{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}
.toolbar input{flex:1;min-width:200px;padding:8px 10px;border-radius:6px;
border:1px solid var(--border);background:var(--card);color:var(--text)}
details.f{background:var(--card);border:1px solid var(--border);border-radius:8px;margin:6px 0}
details.f summary{display:flex;gap:10px;align-items:baseline;padding:10px 14px;cursor:pointer;
list-style:none;flex-wrap:wrap}
details.f summary::-webkit-details-marker{display:none}
details.f .body{padding:0 14px 14px;border-top:1px solid var(--border)}
.sev{font-size:11px;font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:99px;
color:#fff;background:var(--c);white-space:nowrap}
.rid{font:12px ui-monospace,Consolas,monospace;color:var(--muted)}
.title{font-weight:600}.loc{flex-basis:100%;font-size:13px;color:var(--muted)}
.supp{opacity:.6}
.tag{font-size:11px;border:1px solid var(--border);border-radius:4px;padding:1px 6px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:12px 0 0}
dt{color:var(--muted);font-size:13px}dd{margin:0}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);
border-radius:8px;overflow:hidden;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600;text-transform:uppercase}
.empty{padding:24px;text-align:center;color:var(--ok);font-weight:600}
.tw{overflow-x:auto}
"""

_JS = """
const off=new Set();const q=document.getElementById('q');
function apply(){const t=q.value.toLowerCase();let shown=0;
document.querySelectorAll('details.f').forEach(d=>{const ok=!off.has(d.dataset.sev)&&
(!t||d.textContent.toLowerCase().includes(t));d.hidden=!ok;if(ok)shown++;});
document.getElementById('shown').textContent=shown;}
document.querySelectorAll('.card').forEach(c=>c.addEventListener('click',()=>{
const s=c.dataset.sev;off.has(s)?off.delete(s):off.add(s);c.classList.toggle('off');apply();}));
q.addEventListener('input',apply);apply();
"""


def _finding_html(f: Finding, dimmed: bool) -> str:
    meta = RULES_BY_ID[f.rule_id].meta if f.rule_id in RULES_BY_ID else None
    refs = ""
    if meta and meta.references:
        refs = (
            "<dt>References</dt><dd>"
            + "<br>".join(
                f'<a href="{escape(r)}" rel="noopener">{escape(r)}</a>' for r in meta.references
            )
            + "</dd>"
        )
    tags = ""
    if meta:
        tags = " ".join(
            f'<span class="tag">{escape(t)}</span>' for t in (meta.cwe, meta.masvs) if t
        )
    if f.library:
        tags += f' <span class="tag">library: {escape(f.library)}</span>'
    if f.baseline_state:
        tags += f' <span class="tag">baseline: {escape(f.baseline_state)}</span>'
    supp = ""
    if f.suppressed:
        supp = f"<dt>Suppressed</dt><dd>{escape(f.suppression_reason or '')}</dd>"
    evidence = f"<dt>Evidence</dt><dd><code>{escape(f.evidence)}</code></dd>" if f.evidence else ""
    return f"""<details class="f{" supp" if dimmed else ""}" data-sev="{f.severity.label}">
<summary><span class="sev" style="--c:var(--{f.severity.label})">{f.severity.label}</span>
<span class="rid">{escape(f.rule_id)}</span><span class="title">{escape(f.title)}</span>{tags}
<span class="loc"><code>{escape(str(f.location))}</code></span></summary>
<div class="body"><dl><dt>Details</dt><dd>{escape(f.message)}</dd>{evidence}
<dt>Remediation</dt><dd>{escape(f.remediation)}</dd>{refs}{supp}</dl></div></details>"""


def render_html(result: ScanResult) -> str:
    counts = result.counts()
    cards = "".join(
        f'<div class="card" data-sev="{label}" style="--c:var(--{label})" '
        f'title="Click to hide/show"><div class="n">{n}</div><div class="l">{label}</div></div>'
        for label, n in counts.items()
    )
    # Findings that do not count (suppressed, library, baseline) are shown dimmed.
    gating = {id(f) for f in result.gating_findings}
    findings = "".join(_finding_html(f, id(f) not in gating) for f in result.findings)
    if not result.findings:
        findings = '<div class="empty">No findings - nice work.</div>'
    rules_rows = "".join(
        f"<tr><td><code>{escape(m.id)}</code></td><td>{escape(m.title)}</td>"
        f"<td>{m.severity.label}</td><td>{escape(m.category)}</td>"
        f"<td>{escape(m.cwe or '')}</td></tr>"
        for m in result.rules
    )
    errors = ""
    if result.errors:
        errors = (
            "<h2>Rule errors</h2><ul>"
            + "".join(
                f"<li><code>{escape(e.rule_id)}</code>: {escape(e.error)}</li>"
                for e in result.errors
            )
            + "</ul>"
        )
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    suppressed = len(result.findings) - len(result.active_findings)
    in_libraries = len(result.separated_findings)
    in_baseline = (
        f", {result.baseline.unchanged} unchanged since baseline" if result.baseline else ""
    )
    worst = max((f.severity for f in result.gating_findings), default=None)
    verdict = f"Highest severity: {worst.label}" if worst is not None else "No active findings"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>APKGuard report - {escape(result.package)}</title><style>{_CSS}</style></head>
<body><main>
<h1>APKGuard security report</h1>
<div class="muted">{escape(verdict)} &middot; generated {generated} by APKGuard
{escape(result.tool_version)}</div>
<div class="meta">
<div><b>Package</b><code>{escape(result.package)}</code></div>
<div><b>Version</b>{escape(result.version_name or "-")}</div>
<div><b>minSdk / targetSdk</b>{result.min_sdk} / {result.target_sdk}</div>
<div><b>APK</b><code>{escape(result.apk_path)}</code></div>
<div><b>Scan time</b>{result.duration_s:.2f}s</div>
</div>
<div class="cards">{cards}</div>
<h2>Findings <span class="muted">(<span id="shown">{len(result.findings)}</span> shown,
{suppressed} suppressed, {in_libraries} in third-party libraries{in_baseline})</span></h2>
<div class="toolbar"><input id="q" type="search" placeholder="Filter by text, rule, class...">
</div>
{findings}
{errors}
<h2>Rules executed</h2>
<div class="tw"><table><thead><tr><th>ID</th><th>Title</th><th>Default severity</th>
<th>Category</th><th>CWE</th></tr></thead><tbody>{rules_rows}</tbody></table></div>
</main><script>{_JS}</script></body></html>
"""


__all__ = ["Severity", "render_html"]
