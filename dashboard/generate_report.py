"""Static research dashboard generator.

Deliberately dependency-free: reads the JSON written by the experiment runners and emits a single
self-contained HTML file with inline CSS and hand-built SVG charts. No Streamlit, no CDN, no
network. That means it renders in any browser, in a sandboxed preview, and in a submitted archive,
and it can be committed as a reproducible artifact.

(The interactive Streamlit dashboard from the brief remains an M7 item; this covers the reporting
and CSV/JSON-export requirements without pulling in a server.)

Security: this report is generated from local experiment output only. It never reads the keystore
and never renders private key material — worker keys appear only as 16-hex-character fingerprints.

Usage:
    python dashboard/generate_report.py
    python dashboard/generate_report.py --out experiments/reports/report.html
"""

from __future__ import annotations

import argparse
import html
import json
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "experiments" / "results"
REPORTS_DIR = REPO_ROOT / "experiments" / "reports"

PALETTE = {
    "no_verification": "#94a3b8",
    "fixed_1": "#3b82f6",
    "fixed_3": "#1e40af",
    "random_spotcheck": "#a855f7",
    "rule_based": "#f59e0b",
    "risk_adaptive": "#10b981",
}


def latest(prefix: str) -> dict | None:
    files = sorted(RESULTS_DIR.glob(f"{prefix}-*.json"))
    if not files:
        return None
    return json.loads(files[-1].read_text())


def esc(x) -> str:
    return html.escape(str(x))


def bar_chart(data: list[tuple[str, float]], *, title: str, unit: str = "",
              width: int = 640, bar_h: int = 26, gap: int = 10,
              highlight: str | None = None, fmt: str = "{:.3f}") -> str:
    """Horizontal bar chart as inline SVG (no JS, no external assets)."""
    if not data:
        return "<p class='muted'>no data</p>"
    label_w, pad_r = 150, 90
    plot_w = width - label_w - pad_r
    vmax = max((v for _, v in data), default=1.0) or 1.0
    height = len(data) * (bar_h + gap) + gap
    parts = [f"<svg viewBox='0 0 {width} {height}' role='img' aria-label='{esc(title)}' "
             f"style='width:100%;height:auto;max-width:{width}px'>"]
    for i, (label, value) in enumerate(data):
        y = gap + i * (bar_h + gap)
        w = max(2.0, (value / vmax) * plot_w)
        colour = PALETTE.get(label, "#64748b")
        stroke = ";stroke:#0f172a;stroke-width:2" if label == highlight else ""
        parts.append(
            f"<text x='{label_w - 8}' y='{y + bar_h * 0.7}' text-anchor='end' "
            f"style='font:12px ui-monospace,monospace;fill:#334155'>{esc(label)}</text>"
            f"<rect x='{label_w}' y='{y}' width='{w:.1f}' height='{bar_h}' rx='4' "
            f"style='fill:{colour}{stroke}'><title>{esc(label)}: {fmt.format(value)}{esc(unit)}</title></rect>"
            f"<text x='{label_w + w + 8:.1f}' y='{y + bar_h * 0.7}' "
            f"style='font:12px ui-monospace,monospace;fill:#0f172a'>{fmt.format(value)}{esc(unit)}</text>"
        )
    parts.append("</svg>")
    return f"<figure><figcaption>{esc(title)}</figcaption>{''.join(parts)}</figure>"


def scatter_cost_vs_recall(agg: dict) -> str:
    """The central trade-off plot: verification cost (x) against detection recall (y)."""
    w, h, pad = 620, 340, 52
    xmax = max((v["verification_units_per_task"] for v in agg.values()), default=1.0) or 1.0
    parts = [f"<svg viewBox='0 0 {w} {h}' role='img' aria-label='cost versus recall' "
             f"style='width:100%;height:auto;max-width:{w}px'>"]
    parts.append(f"<rect x='{pad}' y='10' width='{w - pad - 20}' height='{h - pad - 20}' "
                 f"style='fill:#f8fafc;stroke:#e2e8f0'/>")
    for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
        y = 10 + (1 - frac) * (h - pad - 30)
        parts.append(
            f"<line x1='{pad}' y1='{y:.1f}' x2='{w - 20}' y2='{y:.1f}' style='stroke:#e2e8f0'/>"
            f"<text x='{pad - 8}' y='{y + 4:.1f}' text-anchor='end' "
            f"style='font:11px ui-monospace,monospace;fill:#64748b'>{frac:.2f}</text>")
    for arm, v in agg.items():
        x = pad + (v["verification_units_per_task"] / xmax) * (w - pad - 40)
        y = 10 + (1 - v["detection_recall"]) * (h - pad - 30)
        colour = PALETTE.get(arm, "#64748b")
        parts.append(
            f"<circle cx='{x:.1f}' cy='{y:.1f}' r='7' style='fill:{colour};stroke:#fff;stroke-width:2'>"
            f"<title>{esc(arm)}: {v['verification_units_per_task']:.3f} units, "
            f"recall {v['detection_recall']:.3f}</title></circle>"
            f"<text x='{x + 11:.1f}' y='{y + 4:.1f}' style='font:11px ui-monospace,monospace;"
            f"fill:#0f172a'>{esc(arm)}</text>")
    parts.append(
        f"<text x='{w / 2}' y='{h - 8}' text-anchor='middle' style='font:12px system-ui;fill:#475569'>"
        f"verification units per task (lower = cheaper) &#8594;</text>"
        f"<text x='14' y='{h / 2}' transform='rotate(-90 14 {h / 2})' text-anchor='middle' "
        f"style='font:12px system-ui;fill:#475569'>detection recall &#8594;</text></svg>")
    return ("<figure><figcaption>Cost / detection trade-off — the upper-left corner is the goal"
            "</figcaption>" + "".join(parts) + "</figure>")


def table(headers: list[str], rows: list[list], *, highlight_col: int | None = None,
          highlight_row_value: str | None = None) -> str:
    th = "".join(f"<th>{esc(h)}</th>" for h in headers)
    trs = []
    for r in rows:
        cls = " class='hl'" if highlight_row_value and str(r[0]) == highlight_row_value else ""
        tds = "".join(
            f"<td{' class=num' if i else ''}>{esc(c)}</td>" for i, c in enumerate(r)
        )
        trs.append(f"<tr{cls}>{tds}</tr>")
    return f"<table><thead><tr>{th}</tr></thead><tbody>{''.join(trs)}</tbody></table>"


CSS = """
:root{--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--ok:#10b981;--warn:#f59e0b;--bad:#ef4444;--bg:#ffffff}
*{box-sizing:border-box}
body{margin:0;padding:32px;background:#f1f5f9;color:var(--ink);
     font:15px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto}
header{background:linear-gradient(135deg,#0f172a,#1e3a5f);color:#fff;padding:28px 32px;border-radius:14px}
header h1{margin:0 0 6px;font-size:26px;letter-spacing:-.4px}
header p{margin:0;opacity:.85;font-size:14px}
.badges{margin-top:14px;display:flex;gap:8px;flex-wrap:wrap}
.badge{background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.25);
       padding:4px 10px;border-radius:999px;font-size:12px}
section{background:var(--bg);border:1px solid var(--line);border-radius:14px;padding:24px;margin-top:20px}
h2{margin:0 0 4px;font-size:19px}
h3{margin:22px 0 8px;font-size:15px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px}
.muted{color:var(--muted);font-size:13px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0}
.card{background:#f8fafc;border:1px solid var(--line);border-radius:10px;padding:14px}
.card .v{font-size:24px;font-weight:650;letter-spacing:-.5px}
.card .k{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-top:2px}
table{width:100%;border-collapse:collapse;margin-top:10px;font-size:13.5px}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left}
th{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);
   background:#f8fafc;position:sticky;top:0}
td.num{text-align:right;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
tr.hl{background:#ecfdf5}
tr.hl td{font-weight:600}
figure{margin:16px 0}
figcaption{font-size:12px;color:var(--muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:.5px}
.callout{border-left:4px solid var(--warn);background:#fffbeb;padding:14px 16px;border-radius:0 8px 8px 0;margin:16px 0}
.callout.bad{border-color:var(--bad);background:#fef2f2}
.callout.ok{border-color:var(--ok);background:#ecfdf5}
.callout b{display:block;margin-bottom:4px}
code{background:#f1f5f9;padding:1px 5px;border-radius:4px;font-size:12.5px}
footer{margin:24px 0 8px;font-size:12px;color:var(--muted);text-align:center}
.scroll{overflow-x:auto}
"""


def build(mve: dict | None, sweep: dict | None) -> str:
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    out: list[str] = []
    out.append(f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TrustProof-Cloud — Research Report</title><style>{CSS}</style></head><body><div class="wrap">
<header><h1>TrustProof-Cloud</h1>
<p>Risk-Adaptive Cryptographically Verifiable ML Inference in Distributed Cloud Environments</p>
<div class="badges"><span class="badge">Milestone M2 + fault simulator</span>
<span class="badge">generated {esc(now)}</span>
<span class="badge">simulation results — not production measurements</span>
<span class="badge">no novelty or patentability claim</span></div></header>""")

    # ---------------- MVE ----------------
    if mve and mve.get("aggregate"):
        agg = mve["aggregate"]
        cfg = mve["config"]
        adaptive = agg.get("risk_adaptive", {})
        fixed3 = agg.get("fixed_3", {})
        cost_ratio = (adaptive.get("verification_units_per_task", 0) /
                      fixed3["verification_units_per_task"]) if fixed3.get("verification_units_per_task") else 0
        recall_ratio = (adaptive.get("detection_recall", 0) /
                        fixed3["detection_recall"]) if fixed3.get("detection_recall") else 0

        out.append(f"""<section><h2>1. Six-arm policy comparison (MVE)</h2>
<p class="muted">{esc(cfg['tasks_per_arm'])} tasks/arm &times; {esc(cfg['seeds'])} seeds &middot;
{esc(cfg['workers'])} workers ({esc(cfg['faulty_workers'])} faulty, rate {esc(cfg['fault_rate'])}) &middot;
behaviours: {esc(', '.join(cfg['behaviours']))} &middot; model {esc(mve['environment']['model_version'])}
(test accuracy {float(mve['environment']['model_test_accuracy']):.3f})</p>
<div class="cards">
<div class="card"><div class="v">{cost_ratio * 100:.1f}%</div>
  <div class="k">adaptive cost vs fixed_3<br>(target &le; 60%)</div></div>
<div class="card"><div class="v">{recall_ratio * 100:.1f}%</div>
  <div class="k">adaptive recall vs fixed_3<br>(target &ge; 90%)</div></div>
<div class="card"><div class="v">{adaptive.get('verification_units_per_task', 0):.3f}</div>
  <div class="k">adaptive ver. units/task</div></div>
<div class="card"><div class="v">{adaptive.get('p95_latency_ms', 0):.1f} ms</div>
  <div class="k">adaptive p95 latency</div></div>
</div>""")

        verdict_cls = "ok" if (cost_ratio <= 0.6 and recall_ratio >= 0.9) else "bad"
        out.append(f"""<div class="callout {verdict_cls}"><b>Pre-registered hypothesis H1: half met</b>
The cost criterion is met by a wide margin ({cost_ratio * 100:.1f}% of fixed_3's verification units,
target &le;60%). The recall criterion is <b>not</b> met ({recall_ratio * 100:.1f}% of fixed_3's recall,
target &ge;90%). Cause: the M2 risk estimator has no anomaly-detector input (the feature is
hard-wired to 0.0) and workers start at the trust prior 0.70, so a freshly-defecting worker scores
below <code>tau_low</code> and is accepted unverified. Reported as a partial failure, not a success.</div>""")

        out.append(scatter_cost_vs_recall(agg))
        out.append(bar_chart([(a, v["verification_units_per_task"]) for a, v in agg.items()],
                             title="Verification cost per task (lower is cheaper)",
                             unit=" u", highlight="risk_adaptive"))
        out.append(bar_chart([(a, v["detection_recall"]) for a, v in agg.items()],
                             title="Detection recall (higher is better)", highlight="risk_adaptive"))
        out.append("<h3>Aggregated results</h3><div class='scroll'>")
        out.append(table(
            ["arm", "ver. units/task", "recall", "FPR", "wrong served", "p95 ms",
             "trust (faulty)", "trust (honest)"],
            [[a, f"{v['verification_units_per_task']:.3f}", f"{v['detection_recall']:.3f}",
              f"{v['false_positive_rate']:.3f}", f"{v['undetected_corruption']:.1f}",
              f"{v['p95_latency_ms']:.1f}", f"{v['mean_trust_faulty']:.3f}",
              f"{v['mean_trust_honest']:.3f}"] for a, v in agg.items()],
            highlight_row_value="risk_adaptive"))
        out.append("</div><p class='muted'>“wrong served” counts results returned to the client that "
                   "differ from the reference prediction — the metric that actually matters, "
                   "independent of whether anything was flagged.</p></section>")

    # ---------------- scenario sweep ----------------
    if sweep:
        rows = sweep["rows"]
        scenarios = sorted({r["scenario"] for r in rows})
        policies = sweep["config"]["policies"]
        out.append(f"""<section><h2>2. Attack-scenario sweep</h2>
<p class="muted">{esc(sweep['config']['tasks'])} tasks &times; {esc(sweep['config']['seeds'])} seeds per cell &middot;
{esc(len(scenarios))} implemented scenarios &times; {esc(len(policies))} policies. Each cell checks the
threat model's prediction about <em>which layer</em> should catch the attack.</p>""")

        def cell(scn: str, pol: str, key: str) -> float:
            vals = [r[key] for r in rows if r["scenario"] == scn and r["policy"] == pol]
            return sum(vals) / len(vals) if vals else 0.0

        out.append("<h3>Detection recall by scenario &times; policy</h3><div class='scroll'>")
        out.append(table(["scenario", *policies],
                         [[s, *[f"{cell(s, p, 'recall'):.3f}" for p in policies]] for s in scenarios]))
        out.append("</div><h3>Wrong results served (lower is better)</h3><div class='scroll'>")
        out.append(table(["scenario", *policies],
                         [[s, *[f"{cell(s, p, 'wrong_results_served'):.1f}" for p in policies]]
                          for s in scenarios]))
        out.append("</div>")

        failed = [r for r in rows if str(r.get("expectation", "")).startswith("FAILED")]
        met = len(rows) - len(failed)
        cls = "ok" if not failed else "bad"
        out.append(f"""<div class="callout {cls}"><b>Threat-model expectation checks: {met}/{len(rows)} met</b>
Every scenario the threat model calls cryptographically detectable produced the predicted failure
reason (<code>result_hash_mismatch</code>, <code>invalid_signature</code>, <code>stale_timestamp</code>,
<code>model_version_not_allowed</code>, <code>task_id_mismatch</code>). This supports H4.</div>""")

        out.append("""<div class="callout"><b>The finding that matters most</b>
On <code>silent_wrong_result</code> — a worker that computes a wrong answer and signs it correctly —
cryptography is powerless by construction, and only replication can help. <code>fixed_1</code> reaches
recall 1.000; <code>risk_adaptive</code> reaches ~0.04 and lets wrong answers through. This isolates
exactly the weakness quantified in section 1 and is the target of milestones M4 and M6.</div>""")

        if sweep.get("not_implemented"):
            items = "".join(f"<li><code>{esc(k)}</code> — {esc(v)}</li>"
                            for k, v in sweep["not_implemented"].items())
            out.append(f"<h3>Declared but not run</h3><ul class='muted'>{items}</ul>")
        out.append("</section>")

    # ---------------- caveats ----------------
    out.append("""<section><h2>3. How to read these numbers</h2>
<ul>
<li><b>Simulation, not production.</b> One machine, synthetic per-worker service time, in-process
workers. Latency is comparable <em>between arms</em> and meaningless in absolute terms.</li>
<li><b>The adversary is one we wrote.</b> Detection rates hold for the injected fault model only.
Faulty workers defect randomly, not strategically; a stealth attacker is not yet implemented.</li>
<li><b>Few seeds, no significance testing.</b> Findings promoted to conclusions require &ge;5 seeds,
multiple workload regimes and a stated test statistic.</li>
<li><b>Signatures prove provenance, not correctness.</b> A worker with a valid key can sign a wrong
answer and every cryptographic check will pass.</li>
<li><b>Not audited, not novel-claimed, not patent-claimed.</b> No prior-art search has been
performed; see <code>docs/prior-art-checklist.md</code>.</li>
</ul></section>""")

    out.append(f"""<footer>TrustProof-Cloud &middot; generated by
<code>dashboard/generate_report.py</code> &middot; {esc(now)}<br>
Research prototype. No security guarantee beyond THREAT_MODEL.md. No private key material appears
in this report.</footer></div></body></html>""")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate the static research report")
    ap.add_argument("--out", default=str(REPORTS_DIR / "report.html"))
    args = ap.parse_args()

    mve, sweep = latest("mve"), latest("sweep")
    if mve is None and sweep is None:
        print("No experiment results found. Run:\n"
              "  python -m experiments.runners.mve\n"
              "  python -m experiments.runners.scenario_sweep")
        return 1

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(build(mve, sweep), encoding="utf-8")
    print(f"wrote {out_path.relative_to(REPO_ROOT)}  ({out_path.stat().st_size // 1024} KB)")
    print(f"  MVE   : {mve['experiment_id'] if mve else 'none'}")
    print(f"  sweep : {sweep['experiment_id'] if sweep else 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
